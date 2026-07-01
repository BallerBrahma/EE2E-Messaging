"""Async websocket client for talking to the relay server.

A single background task reads all incoming frames: request/response pairs
(register, login, upload_keys, fetch_bundle, send_message) are correlated
by simply waiting for the next non-pushed frame, since this client only
ever has one request in flight at a time. Server-pushed `incoming_message`
frames are routed to `on_message` instead of the response queue.

NOTE: This module is intentionally used from a single asyncio task at a
time (the Qt/qasync event loop, or a test script) -- it is not safe to call
request methods concurrently from multiple tasks.
"""
from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from typing import Awaitable, Callable

from websockets.asyncio.client import ClientConnection, connect

from crypto import primitives as prim
from crypto.identity import KeyStore, PrekeyBundle


class ServerError(Exception):
    pass


# must match server/server.py's MAX_MESSAGE_SIZE -- attachments can approach it.
MAX_MESSAGE_SIZE = 20 * 1024 * 1024


@dataclass
class IncomingMessage:
    id: int
    sender: str
    payload: dict
    created_at: float


class NetworkClient:
    def __init__(self, uri: str):
        self.uri = uri
        self._ws: ClientConnection | None = None
        self._response_queue: asyncio.Queue[dict] = asyncio.Queue()
        self._reader_task: asyncio.Task | None = None
        self.on_message: Callable[[IncomingMessage], Awaitable[None]] | None = None
        self.on_presence: Callable[[str, bool], Awaitable[None]] | None = None
        self.on_presence_snapshot: Callable[[list[str]], Awaitable[None]] | None = None
        self.username: str | None = None

    async def connect(self) -> None:
        self._ws = await connect(self.uri, max_size=MAX_MESSAGE_SIZE)
        self._reader_task = asyncio.create_task(self._read_loop())

    async def close(self) -> None:
        if self._reader_task is not None:
            self._reader_task.cancel()
        if self._ws is not None:
            await self._ws.close()

    async def _read_loop(self) -> None:
        assert self._ws is not None
        async for raw in self._ws:
            msg = json.loads(raw)
            msg_type = msg.get("type")
            if msg_type == "incoming_message":
                if self.on_message is not None:
                    await self.on_message(IncomingMessage(
                        id=msg["id"], sender=msg["sender"], payload=msg["payload"], created_at=msg["created_at"],
                    ))
            elif msg_type == "presence":
                if self.on_presence is not None:
                    await self.on_presence(msg["username"], msg["online"])
            elif msg_type == "presence_snapshot":
                if self.on_presence_snapshot is not None:
                    await self.on_presence_snapshot(msg["online_usernames"])
            else:
                await self._response_queue.put(msg)

    async def _request(self, request: dict) -> dict:
        assert self._ws is not None, "call connect() first"
        await self._ws.send(json.dumps(request))
        response = await self._response_queue.get()
        if response.get("type") == "error":
            raise ServerError(response.get("message", "unknown server error"))
        return response

    # -- account ---------------------------------------------------------------

    async def register(self, username: str, password: str) -> None:
        await self._request({"type": "register", "username": username, "password": password})

    async def login(self, username: str, password: str) -> None:
        response = await self._request({"type": "login", "username": username, "password": password})
        self.username = response["username"]

    # -- keys ---------------------------------------------------------------------

    async def upload_keys(self, keystore: KeyStore) -> None:
        bundle = keystore.public_bundle(include_one_time=False)
        request = {
            "type": "upload_keys",
            "identity_pub_dh": base64.b64encode(bundle.identity_pub_dh).decode(),
            "identity_pub_sign": base64.b64encode(bundle.identity_pub_sign).decode(),
            "signed_prekey_id": bundle.signed_prekey_id,
            "signed_prekey_pub": base64.b64encode(bundle.signed_prekey_pub).decode(),
            "signed_prekey_sig": base64.b64encode(bundle.signed_prekey_sig).decode(),
            "one_time_prekeys": [
                {"key_id": otk.key_id, "public_key": base64.b64encode(prim.x25519_pub_bytes(otk.public_key)).decode()}
                for otk in keystore.one_time_prekeys.values()
            ],
        }
        await self._request(request)

    async def fetch_bundle(self, username: str) -> PrekeyBundle | None:
        response = await self._request({"type": "fetch_bundle", "username": username})
        if response["bundle"] is None:
            return None
        return PrekeyBundle.from_json(response["bundle"])

    # -- messaging ------------------------------------------------------------------

    async def send_message(self, recipient: str, payload: dict) -> None:
        await self._request({"type": "send_message", "recipient": recipient, "payload": payload})
