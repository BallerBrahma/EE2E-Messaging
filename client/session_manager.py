"""Ties crypto (X3DH + Double Ratchet) to local storage and the network.

This is the layer the GUI talks to. Every ratchet-encrypted plaintext is a
small JSON "envelope" (see _build_envelope) rather than a raw string, which
is what makes deletes, group messages and attachments possible on top of the
same pairwise Double Ratchet sessions built for 1:1 chat. Group conversations
are pure pairwise fan-out: one envelope (one id) gets encrypted separately to
every other member's existing/newly-established 1:1 session -- there is no
group-level cryptographic key.
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass, field

from crypto import x3dh
from crypto.identity import KeyStore
from crypto.ratchet import RatchetMessage, RatchetState
from client.network import IncomingMessage, NetworkClient
from client.storage import (
    ConversationSummary,
    LocalStorage,
    StoredMessage,
    group_conversation_id,
    is_group_conversation,
)

ONE_TIME_PREKEY_TARGET = 20
ATTACHMENT_MAX_BYTES = 10 * 1024 * 1024
AVATAR_MAX_BYTES = 2 * 1024 * 1024


@dataclass
class IncomingEvent:
    kind: str  # "message" | "delete" | "group_invite" |
    # "group_member_added" | "group_member_removed" | "avatar_update"
    conversation_id: str
    sender: str
    timestamp: float
    message_id: str | None = None
    message_kind: str | None = None  # "text" | "attachment" | "system", when kind == "message"
    body: dict = field(default_factory=dict)


class SessionManager:
    def __init__(self, keystore: KeyStore, storage: LocalStorage, network: NetworkClient):
        self.keystore = keystore
        self.storage = storage
        self.network = network

    @property
    def username(self) -> str:
        return self.keystore.username

    async def publish_keys(self) -> None:
        """Upload identity/signed-prekey/one-time-prekeys; top up if running low."""
        if self.keystore.top_up_one_time_prekeys(ONE_TIME_PREKEY_TARGET):
            self.storage.save_keystore(self.keystore)
        await self.network.upload_keys(self.keystore)

    # -- recipient resolution --------------------------------------------------------

    def _recipients_for(self, conversation_id: str) -> list[str]:
        if is_group_conversation(conversation_id):
            group_id = conversation_id.split(":", 1)[1]
            return [m for m in self.storage.group_members(group_id) if m != self.username]
        return [conversation_id]

    # -- low-level: encrypt+send one envelope to one recipient -----------------------

    async def _send_envelope_to(self, recipient_username: str, envelope: dict) -> None:
        session = self.storage.load_session(recipient_username)
        x3dh_header_json = None

        if session is None:
            bundle = await self.network.fetch_bundle(recipient_username)
            if bundle is None:
                raise ValueError(f"no such user or no published keys: {recipient_username}")
            result, header = x3dh.initiate(self.keystore, bundle)
            session = RatchetState.init_as_initiator(
                shared_secret=result.shared_secret,
                associated_data=result.associated_data,
                remote_ratchet_pub=bundle.signed_prekey_pub,
            )
            x3dh_header_json = header.to_json()

        ratchet_message = session.encrypt(_envelope_bytes(envelope))
        payload = {"x3dh_header": x3dh_header_json, "ratchet_message": ratchet_message.to_json()}
        await self.network.send_message(recipient_username, payload)
        self.storage.save_session(recipient_username, session)

    async def _fan_out(self, conversation_id: str, envelope: dict) -> None:
        for recipient in self._recipients_for(conversation_id):
            await self._send_envelope_to(recipient, envelope)

    def _require_group_membership(self, conversation_id: str) -> None:
        if is_group_conversation(conversation_id):
            group_id = conversation_id.split(":", 1)[1]
            if self.username not in self.storage.group_members(group_id):
                raise ValueError("you are no longer a member of this group")

    # -- sending: text / attachment ---------------------------------------------------

    async def send_text(self, conversation_id: str, text: str) -> str:
        self._require_group_membership(conversation_id)
        message_id = str(uuid.uuid4())
        group_id = conversation_id.split(":", 1)[1] if is_group_conversation(conversation_id) else None
        envelope = {"id": message_id, "type": "text", "group_id": group_id, "body": {"content": text}}
        await self._fan_out(conversation_id, envelope)

        if not is_group_conversation(conversation_id):
            self.storage.add_contact(conversation_id)
        self.storage.add_message(
            conversation_id, self.username, "sent", "text", message_id, envelope["body"],
            timestamp=time.time(),
        )
        return message_id

    async def send_attachment(self, conversation_id: str, filename: str, mime: str, data: bytes) -> str:
        self._require_group_membership(conversation_id)
        if len(data) > ATTACHMENT_MAX_BYTES:
            raise ValueError(f"attachment too large ({len(data)} bytes, max {ATTACHMENT_MAX_BYTES})")
        message_id = str(uuid.uuid4())
        group_id = conversation_id.split(":", 1)[1] if is_group_conversation(conversation_id) else None
        body = {"filename": filename, "mime": mime, "size": len(data), "data_b64": base64.b64encode(data).decode()}
        envelope = {"id": message_id, "type": "attachment", "group_id": group_id, "body": body}
        await self._fan_out(conversation_id, envelope)

        if not is_group_conversation(conversation_id):
            self.storage.add_contact(conversation_id)
        self.storage.add_message(
            conversation_id, self.username, "sent", "attachment", message_id, body,
            timestamp=time.time(),
        )
        return message_id

    # -- delete-for-everyone -----------------------------------------------------------

    async def delete_message(self, conversation_id: str, message_id: str) -> None:
        self.storage.mark_deleted(conversation_id, message_id)
        group_id = conversation_id.split(":", 1)[1] if is_group_conversation(conversation_id) else None
        envelope = {"id": str(uuid.uuid4()), "type": "delete", "group_id": group_id,
                    "body": {"target_id": message_id}}
        await self._fan_out(conversation_id, envelope)

    # -- groups ---------------------------------------------------------------------------

    async def create_group(self, name: str, members: list[str]) -> str:
        group_id = str(uuid.uuid4())
        all_members = sorted(set(members) | {self.username})
        self.storage.create_group(group_id, name, all_members)
        conversation_id = group_conversation_id(group_id)

        envelope = {"id": str(uuid.uuid4()), "type": "group_invite", "group_id": group_id,
                    "body": {"group_id": group_id, "name": name, "members": all_members}}
        for member in all_members:
            if member != self.username:
                await self._send_envelope_to(member, envelope)

        self.storage.add_message(
            conversation_id, None, "sent", "system", str(uuid.uuid4()),
            {"content": "You created this group"}, timestamp=time.time(),
        )
        return group_id

    def groups(self) -> list[tuple[str, str]]:
        return self.storage.list_groups()

    async def add_group_member(self, group_id: str, username: str) -> None:
        conversation_id = group_conversation_id(group_id)
        current_members = self.storage.group_members(group_id)
        if username in current_members:
            return
        self.storage.add_group_member(group_id, username)
        new_roster = sorted(set(current_members) | {username})
        name = self.storage.group_name(group_id) or "Unnamed group"

        invite_envelope = {"id": str(uuid.uuid4()), "type": "group_invite", "group_id": group_id,
                            "body": {"group_id": group_id, "name": name, "members": new_roster}}
        await self._send_envelope_to(username, invite_envelope)

        added_envelope = {"id": str(uuid.uuid4()), "type": "group_member_added", "group_id": group_id,
                           "body": {"group_id": group_id, "added_username": username}}
        for member in current_members:
            if member != self.username:
                await self._send_envelope_to(member, added_envelope)

        self.storage.add_message(
            conversation_id, None, "sent", "system", str(uuid.uuid4()),
            {"content": f"You added {username}"}, timestamp=time.time(),
        )

    async def remove_group_member(self, group_id: str, username: str) -> None:
        conversation_id = group_conversation_id(group_id)
        old_roster = self.storage.group_members(group_id)
        if username not in old_roster:
            return
        self.storage.remove_group_member(group_id, username)

        removed_envelope = {"id": str(uuid.uuid4()), "type": "group_member_removed", "group_id": group_id,
                             "body": {"group_id": group_id, "removed_username": username}}
        for member in old_roster:
            if member != self.username:
                await self._send_envelope_to(member, removed_envelope)

        note = "You left this group" if username == self.username else f"You removed {username}"
        self.storage.add_message(
            conversation_id, None, "sent", "system", str(uuid.uuid4()),
            {"content": note}, timestamp=time.time(),
        )

    # -- profile pictures -------------------------------------------------------------------

    def _known_recipients(self) -> set[str]:
        recipients = set(self.storage.list_contacts())
        for group_id, _name in self.storage.list_groups():
            recipients.update(self.storage.group_members(group_id))
        recipients.discard(self.username)
        return recipients

    async def set_profile_picture(self, image_bytes: bytes, mime: str) -> None:
        if len(image_bytes) > AVATAR_MAX_BYTES:
            raise ValueError(f"image too large ({len(image_bytes)} bytes, max {AVATAR_MAX_BYTES})")
        self.storage.set_avatar(self.username, image_bytes)
        envelope = {"id": str(uuid.uuid4()), "type": "profile_picture", "group_id": None,
                    "body": {"image_b64": base64.b64encode(image_bytes).decode(), "mime": mime}}
        for recipient in self._known_recipients():
            await self._send_envelope_to(recipient, envelope)

    def avatar(self, username: str) -> bytes | None:
        return self.storage.get_avatar(username)

    # -- receiving ------------------------------------------------------------------------

    def _decrypt_envelope(self, incoming: IncomingMessage) -> dict:
        sender = incoming.sender
        payload = incoming.payload
        session = self.storage.load_session(sender)

        if payload.get("x3dh_header") is not None and session is None:
            header = x3dh.InitialMessageHeader.from_json(payload["x3dh_header"])
            result = x3dh.respond(self.keystore, header)
            session = RatchetState.init_as_responder(
                shared_secret=result.shared_secret,
                associated_data=result.associated_data,
                own_ratchet_priv=self.keystore.signed_prekey.private_key,
            )
            # the one-time prekey consumed by x3dh.respond() was removed from
            # the in-memory keystore -- persist that so it can't be reused.
            self.storage.save_keystore(self.keystore)

        if session is None:
            raise ValueError(f"received a message from {sender} with no session and no X3DH init header")

        ratchet_message = RatchetMessage.from_json(payload["ratchet_message"])
        envelope = _envelope_from_bytes(session.decrypt(ratchet_message))
        self.storage.save_session(sender, session)
        return envelope

    def handle_incoming(self, incoming: IncomingMessage) -> IncomingEvent:
        sender = incoming.sender
        ts = incoming.created_at
        envelope = self._decrypt_envelope(incoming)
        envelope_type = envelope["type"]
        group_id = envelope.get("group_id")
        conversation_id = group_conversation_id(group_id) if group_id else sender

        handler = self._ENVELOPE_HANDLERS.get(envelope_type)
        if handler is None:
            raise ValueError(f"unknown envelope type: {envelope_type}")

        if envelope_type not in ("group_invite", "profile_picture") and group_id and not self.storage.group_name(group_id):
            # message for a group we don't know about yet (e.g. local state lost) --
            # degrade gracefully instead of dropping the message.
            self.storage.create_group(group_id, "Unknown group", [sender, self.username])

        return handler(self, sender, conversation_id, group_id, envelope, ts)

    def _on_group_invite(self, sender, _conversation_id, _group_id, envelope, ts) -> IncomingEvent:
        body = envelope["body"]
        self.storage.create_group(body["group_id"], body["name"], body["members"])
        return IncomingEvent(kind="group_invite", conversation_id=group_conversation_id(body["group_id"]),
                              sender=sender, timestamp=ts, body=body)

    def _on_profile_picture(self, sender, _conversation_id, _group_id, envelope, ts) -> IncomingEvent:
        image_bytes = base64.b64decode(envelope["body"]["image_b64"])
        self.storage.set_avatar(sender, image_bytes)
        return IncomingEvent(kind="avatar_update", conversation_id=sender, sender=sender, timestamp=ts,
                              body=envelope["body"])

    def _on_delete(self, sender, conversation_id, _group_id, envelope, ts) -> IncomingEvent:
        target_id = envelope["body"]["target_id"]
        self.storage.mark_deleted(conversation_id, target_id)
        return IncomingEvent(kind="delete", conversation_id=conversation_id, sender=sender,
                              timestamp=ts, message_id=target_id, body=envelope["body"])

    def _on_group_member_added(self, sender, conversation_id, group_id, envelope, ts) -> IncomingEvent:
        added_username = envelope["body"]["added_username"]
        self.storage.add_group_member(group_id, added_username)
        self.storage.add_message(
            conversation_id, None, "received", "system", str(uuid.uuid4()),
            {"content": f"{added_username} was added"}, timestamp=ts,
        )
        return IncomingEvent(kind="group_member_added", conversation_id=conversation_id, sender=sender,
                              timestamp=ts, body=envelope["body"])

    def _on_group_member_removed(self, sender, conversation_id, group_id, envelope, ts) -> IncomingEvent:
        removed_username = envelope["body"]["removed_username"]
        self.storage.remove_group_member(group_id, removed_username)
        note = ("You were removed from the group" if removed_username == self.username
                else f"{removed_username} was removed")
        self.storage.add_message(
            conversation_id, None, "received", "system", str(uuid.uuid4()),
            {"content": note}, timestamp=ts,
        )
        return IncomingEvent(kind="group_member_removed", conversation_id=conversation_id, sender=sender,
                              timestamp=ts, body=envelope["body"])

    def _on_content_message(self, sender, conversation_id, _group_id, envelope, ts) -> IncomingEvent:
        envelope_type = envelope["type"]
        if not is_group_conversation(conversation_id):
            self.storage.add_contact(sender)
        self.storage.add_message(
            conversation_id, sender, "received", envelope_type, envelope["id"], envelope["body"],
            timestamp=ts,
        )
        return IncomingEvent(kind="message", conversation_id=conversation_id, sender=sender, timestamp=ts,
                              message_id=envelope["id"], message_kind=envelope_type, body=envelope["body"])

    _ENVELOPE_HANDLERS = {
        "group_invite": _on_group_invite,
        "profile_picture": _on_profile_picture,
        "delete": _on_delete,
        "group_member_added": _on_group_member_added,
        "group_member_removed": _on_group_member_removed,
        "text": _on_content_message,
        "attachment": _on_content_message,
    }

    # -- read helpers -----------------------------------------------------------------------

    def history(self, conversation_id: str) -> list[StoredMessage]:
        return self.storage.get_messages(conversation_id)

    def conversations(self) -> list[ConversationSummary]:
        return self.storage.list_conversations()

    def contacts(self) -> list[str]:
        return self.storage.list_contacts()

    def set_pinned(self, conversation_id: str, pinned: bool) -> None:
        # purely a local organizational preference -- not synced to the other side(s).
        self.storage.set_pinned(conversation_id, pinned)


def _envelope_bytes(envelope: dict) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def _envelope_from_bytes(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"))
