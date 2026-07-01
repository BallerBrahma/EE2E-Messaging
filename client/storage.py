"""Local, encrypted-at-rest storage for a single client identity.

Everything sensitive (the identity/prekey private keys, per-conversation
ratchet session state, message history, and a server-auth token -- see
below) is stored in SQLite encrypted with a random 256-bit **master key
(MK)**. MK itself is never stored in the clear; it's wrapped ("envelope
encrypted") twice: once by a KEK derived from the user's login password
(Scrypt), and once by a KEK derived from a 12-word BIP39 recovery phrase
(via the `mnemonic` package) generated once at account creation and shown
to the user exactly once. Either factor independently unlocks MK -- this
is the same pattern password managers use for recovery kits. Losing *both*
the password and the recovery phrase means losing access, by design; losing
just one is recoverable via the other (see `unlock_with_recovery` and
`rotate_password`).

The **server-auth token** is a second thing worth calling out: it's a
random value (unrelated to the human password) generated at account
creation and stored MK-encrypted like everything else, then used as the
"password" sent to the relay server's login (see client/api.py). This means
the server never sees anything derived from the user's real password, and
password recovery never needs any server-side coordination -- recovering
MK via the recovery phrase recovers the server-auth token too.

Conversations are addressed by a single `conversation_id` string:
- a bare username (e.g. "bob") for a 1:1 conversation
- "group:<uuid>" for a group conversation

Ratchet *sessions*, however, always stay per-username (pairwise), even for
group conversations -- see client/session_manager.py for the fan-out logic.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass

from mnemonic import Mnemonic

from crypto import primitives as prim
from crypto.identity import KeyStore
from crypto.ratchet import RatchetState

GROUP_PREFIX = "group:"
MASTER_KEY_LEN = 32
SERVER_TOKEN_LEN = 32
RECOVERY_HKDF_INFO = b"E2EE-recovery-kek-v1"

_mnemonic = Mnemonic("english")

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    username TEXT PRIMARY KEY,
    added_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    contact_username TEXT PRIMARY KEY,
    encrypted_state BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL REFERENCES groups(group_id),
    username TEXT NOT NULL,
    PRIMARY KEY (group_id, username)
);

CREATE TABLE IF NOT EXISTS conversation_settings (
    conversation_id TEXT PRIMARY KEY,
    pinned INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS avatars (
    username TEXT PRIMARY KEY,
    encrypted_image BLOB NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    sender_username TEXT,
    direction TEXT NOT NULL CHECK(direction IN ('sent', 'received')),
    kind TEXT NOT NULL DEFAULT 'text',
    encrypted_body BLOB NOT NULL,
    timestamp REAL NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(conversation_id, message_id);
"""


@dataclass
class StoredMessage:
    conversation_id: str
    message_id: str
    sender_username: str | None
    direction: str
    kind: str
    body: dict
    timestamp: float


@dataclass
class ConversationSummary:
    conversation_id: str
    kind: str  # 'dm' | 'group'
    display_name: str
    last_preview: str
    last_timestamp: float
    pinned: bool = False


class WrongPassword(Exception):
    pass


class InvalidRecoveryPhrase(Exception):
    pass


def group_conversation_id(group_id: str) -> str:
    return f"{GROUP_PREFIX}{group_id}"


def is_group_conversation(conversation_id: str) -> bool:
    return conversation_id.startswith(GROUP_PREFIX)


class LocalStorage:
    """Wraps one SQLite file for one local identity. Must be unlocked
    (created or opened) with a password before use."""

    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._enc_key: bytes | None = None

    # -- lifecycle --------------------------------------------------------------

    def is_initialized(self) -> bool:
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'keystore'").fetchone()
        return row is not None

    def create_identity(self, username: str, password: str) -> tuple[KeyStore, str]:
        """Returns (keystore, recovery_phrase). The recovery phrase is only
        ever available here, right after generation -- show it to the user
        once; it isn't retrievable again after this call returns."""
        if self.is_initialized():
            raise ValueError("local storage already has an identity")

        master_key = os.urandom(MASTER_KEY_LEN)
        recovery_phrase = _mnemonic.generate(strength=128)
        server_auth_token = os.urandom(SERVER_TOKEN_LEN).hex()

        password_salt = prim.new_salt()
        password_kek = prim.derive_key_from_password(password, password_salt)
        recovery_kek = self._recovery_kek(recovery_phrase)

        self._enc_key = master_key  # unlocked from here on, so _save_keystore below works
        keystore = KeyStore.generate(username)

        self._save_meta("password_salt", password_salt)
        self._save_meta("wrapped_mk_password", prim.aead_encrypt(password_kek, master_key))
        self._save_meta("wrapped_mk_recovery", prim.aead_encrypt(recovery_kek, master_key))
        self._save_meta("encrypted_server_token", prim.aead_encrypt(master_key, server_auth_token.encode("utf-8")))
        self._save_keystore(keystore)

        return keystore, recovery_phrase

    def _recovery_kek(self, recovery_phrase: str) -> bytes:
        if not _mnemonic.check(recovery_phrase):
            raise InvalidRecoveryPhrase("recovery phrase is invalid (misspelled word or wrong order)")
        entropy = bytes(_mnemonic.to_entropy(recovery_phrase))
        return prim.hkdf(entropy, MASTER_KEY_LEN, salt=None, info=RECOVERY_HKDF_INFO)

    def unlock(self, password: str) -> tuple[KeyStore, str]:
        """Returns (keystore, server_auth_token)."""
        password_salt = self._load_meta("password_salt")
        if password_salt is None:
            raise ValueError("local storage has no identity yet -- call create_identity")
        password_kek = prim.derive_key_from_password(password, password_salt)
        try:
            master_key = prim.aead_decrypt(password_kek, self._load_meta("wrapped_mk_password"))
        except prim.DecryptionError:
            raise WrongPassword("incorrect password")
        return self._finish_unlock(master_key)

    def unlock_with_recovery(self, recovery_phrase: str) -> tuple[KeyStore, str]:
        """Returns (keystore, server_auth_token). Raises InvalidRecoveryPhrase
        for a malformed/mistyped phrase (checksum failure, caught before any
        decryption is attempted) or a well-formed phrase that simply doesn't
        belong to this account (decryption failure)."""
        recovery_kek = self._recovery_kek(recovery_phrase)
        wrapped_mk = self._load_meta("wrapped_mk_recovery")
        if wrapped_mk is None:
            raise ValueError("local storage has no identity yet -- call create_identity")
        try:
            master_key = prim.aead_decrypt(recovery_kek, wrapped_mk)
        except prim.DecryptionError:
            raise InvalidRecoveryPhrase("recovery phrase does not match this account")
        return self._finish_unlock(master_key)

    def _finish_unlock(self, master_key: bytes) -> tuple[KeyStore, str]:
        self._enc_key = master_key
        keystore = KeyStore.from_json(json.loads(prim.aead_decrypt(master_key, self._load_meta("keystore")).decode("utf-8")))
        server_auth_token = prim.aead_decrypt(master_key, self._load_meta("encrypted_server_token")).decode("utf-8")
        return keystore, server_auth_token

    def rotate_password(self, new_password: str) -> None:
        """Re-wraps the (already unlocked) master key under a new password.
        Doesn't touch the master key itself, the recovery-phrase wrapping,
        or any encrypted data -- the recovery phrase keeps working after a
        password reset, same as a password manager's recovery kit."""
        master_key = self._require_unlocked()
        password_salt = prim.new_salt()
        password_kek = prim.derive_key_from_password(new_password, password_salt)
        self._save_meta("password_salt", password_salt)
        self._save_meta("wrapped_mk_password", prim.aead_encrypt(password_kek, master_key))

    def _require_unlocked(self) -> bytes:
        if self._enc_key is None:
            raise ValueError("storage is locked -- call create_identity() or unlock() first")
        return self._enc_key

    def server_auth_token(self) -> str:
        """The relay-login token for the currently unlocked identity (see
        module docstring). Needed after create_identity(), which doesn't
        return it directly since unlock()/unlock_with_recovery() already do."""
        master_key = self._require_unlocked()
        return prim.aead_decrypt(master_key, self._load_meta("encrypted_server_token")).decode("utf-8")

    # -- meta / keystore ----------------------------------------------------------

    def _save_meta(self, key: str, value: bytes) -> None:
        self._conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self._conn.commit()

    def _load_meta(self, key: str) -> bytes | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def _save_keystore(self, keystore: KeyStore) -> None:
        key = self._require_unlocked()
        plaintext = json.dumps(keystore.to_json()).encode("utf-8")
        self._save_meta("keystore", prim.aead_encrypt(key, plaintext))

    def save_keystore(self, keystore: KeyStore) -> None:
        """Persist updated keystore state (e.g. after topping up one-time prekeys)."""
        self._save_keystore(keystore)

    # -- contacts -------------------------------------------------------------------

    def add_contact(self, username: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO contacts (username, added_at) VALUES (?, ?)", (username, time.time())
        )
        self._conn.commit()

    def list_contacts(self) -> list[str]:
        rows = self._conn.execute("SELECT username FROM contacts ORDER BY added_at ASC").fetchall()
        return [r["username"] for r in rows]

    # -- groups ---------------------------------------------------------------------

    def create_group(self, group_id: str, name: str, members: list[str]) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO groups (group_id, name, created_at) VALUES (?, ?, ?)",
                (group_id, name, time.time()),
            )
            self._conn.executemany(
                "INSERT OR IGNORE INTO group_members (group_id, username) VALUES (?, ?)",
                [(group_id, m) for m in members],
            )

    def group_name(self, group_id: str) -> str | None:
        row = self._conn.execute("SELECT name FROM groups WHERE group_id = ?", (group_id,)).fetchone()
        return row["name"] if row else None

    def group_members(self, group_id: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT username FROM group_members WHERE group_id = ? ORDER BY username", (group_id,)
        ).fetchall()
        return [r["username"] for r in rows]

    def list_groups(self) -> list[tuple[str, str]]:
        rows = self._conn.execute("SELECT group_id, name FROM groups ORDER BY created_at ASC").fetchall()
        return [(r["group_id"], r["name"]) for r in rows]

    def add_group_member(self, group_id: str, username: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO group_members (group_id, username) VALUES (?, ?)", (group_id, username)
        )
        self._conn.commit()

    def remove_group_member(self, group_id: str, username: str) -> None:
        self._conn.execute(
            "DELETE FROM group_members WHERE group_id = ? AND username = ?", (group_id, username)
        )
        self._conn.commit()

    # -- ratchet sessions (always per-username, even for group conversations) --------

    def save_session(self, contact_username: str, state: RatchetState) -> None:
        key = self._require_unlocked()
        plaintext = json.dumps(state.to_json()).encode("utf-8")
        blob = prim.aead_encrypt(key, plaintext)
        self._conn.execute(
            "INSERT INTO sessions (contact_username, encrypted_state) VALUES (?, ?) "
            "ON CONFLICT(contact_username) DO UPDATE SET encrypted_state = excluded.encrypted_state",
            (contact_username, blob),
        )
        self._conn.commit()

    def load_session(self, contact_username: str) -> RatchetState | None:
        key = self._require_unlocked()
        row = self._conn.execute(
            "SELECT encrypted_state FROM sessions WHERE contact_username = ?", (contact_username,)
        ).fetchone()
        if row is None:
            return None
        plaintext = prim.aead_decrypt(key, row["encrypted_state"])
        return RatchetState.from_json(json.loads(plaintext.decode("utf-8")))

    # -- pinned conversations -----------------------------------------------------------

    def set_pinned(self, conversation_id: str, pinned: bool) -> None:
        self._conn.execute(
            "INSERT INTO conversation_settings (conversation_id, pinned) VALUES (?, ?) "
            "ON CONFLICT(conversation_id) DO UPDATE SET pinned = excluded.pinned",
            (conversation_id, int(pinned)),
        )
        self._conn.commit()

    def is_pinned(self, conversation_id: str) -> bool:
        row = self._conn.execute(
            "SELECT pinned FROM conversation_settings WHERE conversation_id = ?", (conversation_id,)
        ).fetchone()
        return bool(row["pinned"]) if row else False

    # -- avatars ----------------------------------------------------------------------

    def set_avatar(self, username: str, image_bytes: bytes) -> None:
        key = self._require_unlocked()
        blob = prim.aead_encrypt(key, image_bytes)
        self._conn.execute(
            "INSERT INTO avatars (username, encrypted_image, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(username) DO UPDATE SET encrypted_image = excluded.encrypted_image, "
            "updated_at = excluded.updated_at",
            (username, blob, time.time()),
        )
        self._conn.commit()

    def get_avatar(self, username: str) -> bytes | None:
        key = self._require_unlocked()
        row = self._conn.execute("SELECT encrypted_image FROM avatars WHERE username = ?", (username,)).fetchone()
        if row is None:
            return None
        return prim.aead_decrypt(key, row["encrypted_image"])

    # -- message history ---------------------------------------------------------------

    def _encrypt_body(self, body: dict) -> bytes:
        key = self._require_unlocked()
        return prim.aead_encrypt(key, json.dumps(body).encode("utf-8"))

    def _decrypt_body(self, blob: bytes) -> dict:
        key = self._require_unlocked()
        return json.loads(prim.aead_decrypt(key, blob).decode("utf-8"))

    def add_message(
        self,
        conversation_id: str,
        sender_username: str | None,
        direction: str,
        kind: str,
        message_id: str,
        body: dict,
        timestamp: float | None = None,
    ) -> None:
        ts = timestamp if timestamp is not None else time.time()
        blob = self._encrypt_body(body)
        self._conn.execute(
            "INSERT INTO messages (conversation_id, message_id, sender_username, direction, kind, "
            "encrypted_body, timestamp, deleted) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (conversation_id, message_id, sender_username, direction, kind, blob, ts),
        )
        self._conn.commit()

    def get_messages(self, conversation_id: str) -> list[StoredMessage]:
        rows = self._conn.execute(
            "SELECT message_id, sender_username, direction, kind, encrypted_body, timestamp "
            "FROM messages WHERE conversation_id = ? AND deleted = 0 ORDER BY timestamp ASC",
            (conversation_id,),
        ).fetchall()
        out = []
        for row in rows:
            body = self._decrypt_body(row["encrypted_body"])
            out.append(StoredMessage(
                conversation_id=conversation_id,
                message_id=row["message_id"],
                sender_username=row["sender_username"],
                direction=row["direction"],
                kind=row["kind"],
                body=body,
                timestamp=row["timestamp"],
            ))
        return out

    def mark_deleted(self, conversation_id: str, message_id: str) -> bool:
        cur = self._conn.execute(
            "UPDATE messages SET deleted = 1 WHERE conversation_id = ? AND message_id = ?",
            (conversation_id, message_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    # -- conversation list (sidebar) ---------------------------------------------------

    def list_conversations(self) -> list[ConversationSummary]:
        summaries: dict[str, ConversationSummary] = {}
        for username in self.list_contacts():
            summaries[username] = ConversationSummary(username, "dm", username, "", 0.0)
        for group_id, name in self.list_groups():
            cid = group_conversation_id(group_id)
            summaries[cid] = ConversationSummary(cid, "group", name, "", 0.0)

        rows = self._conn.execute(
            "SELECT conversation_id, kind, sender_username, encrypted_body, timestamp FROM messages "
            "WHERE deleted = 0 ORDER BY timestamp ASC"
        ).fetchall()
        for row in rows:
            cid = row["conversation_id"]
            if cid not in summaries:
                continue  # orphaned message with no contact/group record (shouldn't normally happen)
            body = self._decrypt_body(row["encrypted_body"])
            preview = _preview_text(row["kind"], body)
            summaries[cid] = ConversationSummary(cid, summaries[cid].kind, summaries[cid].display_name,
                                                  preview, row["timestamp"])

        pinned_rows = self._conn.execute("SELECT conversation_id FROM conversation_settings WHERE pinned = 1")
        pinned_ids = {r["conversation_id"] for r in pinned_rows.fetchall()}
        for cid, summary in summaries.items():
            summary.pinned = cid in pinned_ids

        return sorted(summaries.values(), key=lambda s: (not s.pinned, -s.last_timestamp))


def _preview_text(kind: str, body: dict) -> str:
    if kind == "text":
        return body.get("content", "")
    if kind == "attachment":
        return f"\U0001F4CE {body.get('filename', 'attachment')}"
    if kind == "system":
        return body.get("content", "")
    return ""
