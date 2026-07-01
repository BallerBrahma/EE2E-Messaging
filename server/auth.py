"""Account registration/login for the relay server.

This is deliberately separate from the E2E identity keys in crypto/identity.py:
it just gates access to the relay (so random clients can't read someone's
mailbox or impersonate them), it has nothing to do with message
confidentiality, which is guaranteed end-to-end regardless of server auth.
"""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from server.db import Database, User

_hasher = PasswordHasher()


class AuthError(Exception):
    pass


def register(db: Database, username: str, password: str) -> User:
    username = username.strip()
    if not username or len(username) > 64:
        raise AuthError("invalid username")
    if len(password) < 8:
        raise AuthError("password must be at least 8 characters")
    if db.get_user(username) is not None:
        raise AuthError("username already taken")
    password_hash = _hasher.hash(password)
    return db.create_user(username, password_hash)


def login(db: Database, username: str, password: str) -> User:
    user = db.get_user(username.strip())
    if user is None:
        raise AuthError("invalid username or password")
    try:
        _hasher.verify(user.password_hash, password)
    except VerifyMismatchError:
        raise AuthError("invalid username or password")
    return user
