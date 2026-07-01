"""Unit tests for client/storage.py's local-only conversation features
(pinning, sidebar ordering) and password-recovery envelope encryption --
no network/server needed."""
from __future__ import annotations

import os
import time

import pytest

from client.storage import InvalidRecoveryPhrase, LocalStorage, WrongPassword, group_conversation_id


def _make_storage(tmp_path, username: str) -> LocalStorage:
    storage = LocalStorage(os.path.join(str(tmp_path), f"{username}.sqlite3"))
    storage.create_identity(username, "a reasonably strong password")
    return storage


def test_pinned_conversation_sorts_before_more_recent_unpinned(tmp_path):
    storage = _make_storage(tmp_path, "alice")
    storage.add_contact("bob")
    storage.add_contact("carol")

    storage.add_message("bob", "bob", "received", "text", "m1", {"content": "hi"}, timestamp=time.time() - 100)
    storage.add_message("carol", "carol", "received", "text", "m2", {"content": "hey"}, timestamp=time.time())

    # carol is more recent, so she'd normally sort first
    convos = storage.list_conversations()
    assert [c.conversation_id for c in convos] == ["carol", "bob"]
    assert all(not c.pinned for c in convos)

    storage.set_pinned("bob", True)
    convos = storage.list_conversations()
    assert [c.conversation_id for c in convos] == ["bob", "carol"]
    assert next(c for c in convos if c.conversation_id == "bob").pinned is True

    storage.set_pinned("bob", False)
    convos = storage.list_conversations()
    assert [c.conversation_id for c in convos] == ["carol", "bob"]


def test_pin_survives_and_applies_to_group_conversations(tmp_path):
    storage = _make_storage(tmp_path, "alice")
    storage.create_group("g1", "Friends", ["alice", "bob"])
    conversation_id = group_conversation_id("g1")

    assert storage.is_pinned(conversation_id) is False
    storage.set_pinned(conversation_id, True)
    assert storage.is_pinned(conversation_id) is True

    convos = storage.list_conversations()
    assert next(c for c in convos if c.conversation_id == conversation_id).pinned is True


def test_password_and_recovery_unlock_to_same_identity(tmp_path):
    path = os.path.join(str(tmp_path), "alice.sqlite3")
    created = LocalStorage(path)
    keystore, recovery_phrase = created.create_identity("alice", "a reasonably strong password")
    token = created.server_auth_token()

    from_password = LocalStorage(path)
    password_keystore, password_token = from_password.unlock("a reasonably strong password")
    assert password_keystore.username == keystore.username
    assert password_keystore.identity_pub_dh_bytes() == keystore.identity_pub_dh_bytes()
    assert password_token == token

    from_recovery = LocalStorage(path)
    recovery_keystore, recovery_token = from_recovery.unlock_with_recovery(recovery_phrase)
    assert recovery_keystore.username == keystore.username
    assert recovery_keystore.identity_pub_dh_bytes() == keystore.identity_pub_dh_bytes()
    assert recovery_token == token


def test_wrong_password_is_rejected(tmp_path):
    storage = _make_storage(tmp_path, "alice")
    reopened = LocalStorage(storage.path)
    with pytest.raises(WrongPassword):
        reopened.unlock("definitely the wrong password")


def test_malformed_recovery_phrase_is_rejected_before_decryption(tmp_path):
    storage = _make_storage(tmp_path, "alice")
    reopened = LocalStorage(storage.path)
    with pytest.raises(InvalidRecoveryPhrase):
        reopened.unlock_with_recovery("this is not a valid bip39 phrase at all")


def test_valid_but_foreign_recovery_phrase_is_rejected(tmp_path):
    _make_storage(tmp_path, "alice")
    other = LocalStorage(os.path.join(str(tmp_path), "bob.sqlite3"))
    _keystore, bob_phrase = other.create_identity("bob", "another reasonably strong password")

    alice_path = os.path.join(str(tmp_path), "alice.sqlite3")
    reopened = LocalStorage(alice_path)
    with pytest.raises(InvalidRecoveryPhrase):
        reopened.unlock_with_recovery(bob_phrase)


def test_rotate_password_invalidates_old_password_but_not_recovery_phrase(tmp_path):
    path = os.path.join(str(tmp_path), "alice.sqlite3")
    created = LocalStorage(path)
    keystore, recovery_phrase = created.create_identity("alice", "the old password")
    token = created.server_auth_token()

    recovered = LocalStorage(path)
    recovered.unlock_with_recovery(recovery_phrase)
    recovered.rotate_password("a brand new password")

    old_password_attempt = LocalStorage(path)
    with pytest.raises(WrongPassword):
        old_password_attempt.unlock("the old password")

    new_password_attempt = LocalStorage(path)
    new_keystore, new_token = new_password_attempt.unlock("a brand new password")
    assert new_keystore.identity_pub_dh_bytes() == keystore.identity_pub_dh_bytes()
    assert new_token == token

    recovery_still_works = LocalStorage(path)
    still_keystore, still_token = recovery_still_works.unlock_with_recovery(recovery_phrase)
    assert still_keystore.identity_pub_dh_bytes() == keystore.identity_pub_dh_bytes()
    assert still_token == token
