"""Relay server.

Speaks a small JSON-over-websockets protocol. Responsibilities:
- account registration/login (server-side auth only, see auth.py)
- storing/serving public prekey bundles
- relaying opaque ciphertext envelopes between clients, with store-and-
  forward for offline recipients

The server never sees plaintext message content or any private key -- the
`payload` of a `send_message` is an opaque JSON blob produced by
client/session_manager.py (an X3DH init header, if any, plus a Double
Ratchet ciphertext message).
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging

from websockets.asyncio.server import ServerConnection, serve

from server import auth
from server.db import Database

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("relay-server")

# websockets defaults to a 1MB frame cap; raise it comfortably above our
# ~10MB attachment envelope (base64 expansion + JSON overhead).
MAX_MESSAGE_SIZE = 20 * 1024 * 1024


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


class ClientSession:
    def __init__(self, db: Database, connected: dict[str, ServerConnection]):
        self.db = db
        self.connected = connected
        self.user = None  # server.db.User once authenticated

    async def handle(self, ws: ServerConnection) -> None:
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    await self._error(ws, "malformed request")
                    continue
                await self._dispatch(ws, msg)
        finally:
            if self.user is not None and self.connected.get(self.user.username) is ws:
                del self.connected[self.user.username]
                log.info("disconnected: %s", self.user.username)
                await self._broadcast_presence(self.user.username, online=False)

    async def _dispatch(self, ws: ServerConnection, msg: dict) -> None:
        msg_type = msg.get("type")
        try:
            if msg_type == "register":
                await self._handle_register(ws, msg)
            elif msg_type == "login":
                await self._handle_login(ws, msg)
            elif msg_type == "upload_keys":
                await self._require_auth(ws, self._handle_upload_keys, msg)
            elif msg_type == "fetch_bundle":
                await self._require_auth(ws, self._handle_fetch_bundle, msg)
            elif msg_type == "send_message":
                await self._require_auth(ws, self._handle_send_message, msg)
            else:
                await self._error(ws, f"unknown request type: {msg_type}")
        except auth.AuthError as exc:
            await self._error(ws, str(exc))
        except Exception:
            log.exception("error handling %s", msg_type)
            await self._error(ws, "internal server error")

    async def _require_auth(self, ws, handler, msg):
        if self.user is None:
            await self._error(ws, "not authenticated")
            return
        await handler(ws, msg)

    async def _error(self, ws, message: str) -> None:
        await ws.send(json.dumps({"type": "error", "message": message}))

    # -- handlers -------------------------------------------------------------

    async def _handle_register(self, ws, msg: dict) -> None:
        user = auth.register(self.db, msg["username"], msg["password"])
        await ws.send(json.dumps({"type": "register_ok", "username": user.username}))

    async def _handle_login(self, ws, msg: dict) -> None:
        user = auth.login(self.db, msg["username"], msg["password"])
        self.user = user
        self.connected[user.username] = ws
        await ws.send(json.dumps({"type": "login_ok", "username": user.username}))
        online_usernames = [u for u in self.connected if u != user.username]
        await ws.send(json.dumps({"type": "presence_snapshot", "online_usernames": online_usernames}))
        await self._deliver_pending(ws)
        await self._broadcast_presence(user.username, online=True)

    async def _broadcast_presence(self, username: str, online: bool) -> None:
        message = json.dumps({"type": "presence", "username": username, "online": online})
        for other_username, other_ws in list(self.connected.items()):
            if other_username != username:
                await other_ws.send(message)

    async def _handle_upload_keys(self, ws, msg: dict) -> None:
        self.db.upsert_identity(
            self.user.id,
            _unb64(msg["identity_pub_dh"]),
            _unb64(msg["identity_pub_sign"]),
        )
        self.db.upsert_signed_prekey(
            self.user.id,
            msg["signed_prekey_id"],
            _unb64(msg["signed_prekey_pub"]),
            _unb64(msg["signed_prekey_sig"]),
        )
        otks = [(k["key_id"], _unb64(k["public_key"])) for k in msg.get("one_time_prekeys", [])]
        if otks:
            self.db.add_one_time_prekeys(self.user.id, otks)
        await ws.send(json.dumps({"type": "keys_ok"}))

    async def _handle_fetch_bundle(self, ws, msg: dict) -> None:
        bundle = self.db.get_prekey_bundle(msg["username"])
        if bundle is None:
            await ws.send(json.dumps({"type": "bundle", "username": msg["username"], "bundle": None}))
            return
        json_bundle = {
            "identity_pub_dh": _b64(bundle["identity_pub_dh"]),
            "identity_pub_sign": _b64(bundle["identity_pub_sign"]),
            "signed_prekey_id": bundle["signed_prekey_id"],
            "signed_prekey_pub": _b64(bundle["signed_prekey_pub"]),
            "signed_prekey_sig": _b64(bundle["signed_prekey_sig"]),
            "one_time_prekey_id": bundle["one_time_prekey_id"],
            "one_time_prekey_pub": _b64(bundle["one_time_prekey_pub"]) if bundle["one_time_prekey_pub"] else None,
        }
        await ws.send(json.dumps({"type": "bundle", "username": msg["username"], "bundle": json_bundle}))

    async def _handle_send_message(self, ws, msg: dict) -> None:
        recipient = msg["recipient"]
        payload = json.dumps(msg["payload"])
        ok = self.db.enqueue_message(recipient, self.user.username, payload)
        if not ok:
            await self._error(ws, f"no such user: {recipient}")
            return
        await ws.send(json.dumps({"type": "message_sent_ok"}))

        recipient_ws = self.connected.get(recipient)
        if recipient_ws is not None:
            await self._push_pending_to(recipient_ws, recipient)

    async def _deliver_pending(self, ws) -> None:
        await self._push_pending_to(ws, self.user.username)

    async def _push_pending_to(self, ws, username: str) -> None:
        user = self.db.get_user(username)
        if user is None:
            return
        rows = self.db.fetch_pending_messages(user.id)
        delivered_ids = []
        for row in rows:
            await ws.send(json.dumps({
                "type": "incoming_message",
                "id": row["id"],
                "sender": row["sender_username"],
                "payload": json.loads(row["payload"]),
                "created_at": row["created_at"],
            }))
            delivered_ids.append(row["id"])
        self.db.mark_delivered(delivered_ids)


async def run_server(host: str, port: int, db_path: str) -> None:
    db = Database(db_path)
    connected: dict[str, ServerConnection] = {}

    async def handler(ws: ServerConnection) -> None:
        await ClientSession(db, connected).handle(ws)

    log.info("relay server listening on ws://%s:%d (db=%s)", host, port, db_path)
    async with serve(handler, host, port, max_size=MAX_MESSAGE_SIZE):
        await asyncio.Future()  # run forever


def main() -> None:
    parser = argparse.ArgumentParser(description="E2EE relay server")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default="relay_server.sqlite3")
    args = parser.parse_args()
    asyncio.run(run_server(args.host, args.port, args.db))


if __name__ == "__main__":
    main()
