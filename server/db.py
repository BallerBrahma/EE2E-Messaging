"""SQLite persistence for the relay server.

The server only ever stores: account auth data (argon2 password hash),
*public* key material (identity/prekey bundles), and opaque ciphertext
envelopes waiting for delivery. It never sees plaintext messages or any
private key.
"""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    identity_pub_dh BLOB NOT NULL,
    identity_pub_sign BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS signed_prekeys (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    key_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    signature BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    key_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_otk_user_unused ON one_time_prekeys(user_id, used);

CREATE TABLE IF NOT EXISTS mailbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    sender_username TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mailbox_recipient_pending ON mailbox(recipient_id, delivered);
"""


@dataclass
class User:
    id: int
    username: str
    password_hash: str


class Database:
    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    @contextmanager
    def _cursor(self):
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    # -- users --------------------------------------------------------------

    def create_user(self, username: str, password_hash: str) -> User:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, time.time()),
            )
            return User(id=cur.lastrowid, username=username, password_hash=password_hash)

    def get_user(self, username: str) -> User | None:
        row = self._conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        return User(id=row["id"], username=row["username"], password_hash=row["password_hash"]) if row else None

    # -- keys -----------------------------------------------------------------

    def upsert_identity(self, user_id: int, identity_pub_dh: bytes, identity_pub_sign: bytes) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO identities (user_id, identity_pub_dh, identity_pub_sign) VALUES (?, ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET identity_pub_dh=excluded.identity_pub_dh,
                       identity_pub_sign=excluded.identity_pub_sign""",
                (user_id, identity_pub_dh, identity_pub_sign),
            )

    def upsert_signed_prekey(self, user_id: int, key_id: str, public_key: bytes, signature: bytes) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT INTO signed_prekeys (user_id, key_id, public_key, signature) VALUES (?, ?, ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET key_id=excluded.key_id,
                       public_key=excluded.public_key, signature=excluded.signature""",
                (user_id, key_id, public_key, signature),
            )

    def add_one_time_prekeys(self, user_id: int, keys: list[tuple[str, bytes]]) -> None:
        with self._cursor() as cur:
            cur.executemany(
                "INSERT INTO one_time_prekeys (user_id, key_id, public_key, used) VALUES (?, ?, ?, 0)",
                [(user_id, key_id, pub) for key_id, pub in keys],
            )

    def count_unused_one_time_prekeys(self, user_id: int) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM one_time_prekeys WHERE user_id = ? AND used = 0", (user_id,)
        ).fetchone()
        return row["c"]

    def get_prekey_bundle(self, username: str) -> dict | None:
        user = self.get_user(username)
        if user is None:
            return None
        identity = self._conn.execute(
            "SELECT identity_pub_dh, identity_pub_sign FROM identities WHERE user_id = ?", (user.id,)
        ).fetchone()
        spk = self._conn.execute(
            "SELECT key_id, public_key, signature FROM signed_prekeys WHERE user_id = ?", (user.id,)
        ).fetchone()
        if identity is None or spk is None:
            return None

        otk_id, otk_pub = None, None
        with self._cursor() as cur:
            otk = cur.execute(
                "SELECT id, key_id, public_key FROM one_time_prekeys WHERE user_id = ? AND used = 0 LIMIT 1",
                (user.id,),
            ).fetchone()
            if otk is not None:
                cur.execute("UPDATE one_time_prekeys SET used = 1 WHERE id = ?", (otk["id"],))
                otk_id, otk_pub = otk["key_id"], otk["public_key"]

        return {
            "identity_pub_dh": identity["identity_pub_dh"],
            "identity_pub_sign": identity["identity_pub_sign"],
            "signed_prekey_id": spk["key_id"],
            "signed_prekey_pub": spk["public_key"],
            "signed_prekey_sig": spk["signature"],
            "one_time_prekey_id": otk_id,
            "one_time_prekey_pub": otk_pub,
        }

    # -- mailbox --------------------------------------------------------------

    def enqueue_message(self, recipient_username: str, sender_username: str, payload: str) -> bool:
        recipient = self.get_user(recipient_username)
        if recipient is None:
            return False
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO mailbox (recipient_id, sender_username, payload, created_at, delivered) "
                "VALUES (?, ?, ?, ?, 0)",
                (recipient.id, sender_username, payload, time.time()),
            )
        return True

    def fetch_pending_messages(self, user_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT id, sender_username, payload, created_at FROM mailbox "
            "WHERE recipient_id = ? AND delivered = 0 ORDER BY id ASC",
            (user_id,),
        ).fetchall()

    def mark_delivered(self, message_ids: list[int]) -> None:
        if not message_ids:
            return
        with self._cursor() as cur:
            cur.executemany("UPDATE mailbox SET delivered = 1 WHERE id = ?", [(i,) for i in message_ids])
