"""Tests for client/keychain.py. The actual Touch ID prompt needs a real
fingerprint and can't be exercised in an automated test -- these cover the
parts that can be: capability detection, Keychain credential round-trip,
and the local (non-secret) remembered-username marker file."""
from __future__ import annotations

import os

from client import keychain

TEST_USERNAME = "e2ee_test_keychain_user"


def test_is_biometric_available_returns_bool_without_raising():
    result = keychain.is_biometric_available()
    assert isinstance(result, bool)


def test_save_load_delete_credential_roundtrip():
    keychain.delete_credential(TEST_USERNAME)  # ensure a clean slate
    try:
        assert keychain.load_credential(TEST_USERNAME) is None

        keychain.save_credential(TEST_USERNAME, "a test password")
        assert keychain.load_credential(TEST_USERNAME) == "a test password"

        keychain.save_credential(TEST_USERNAME, "an updated password")
        assert keychain.load_credential(TEST_USERNAME) == "an updated password"

        keychain.delete_credential(TEST_USERNAME)
        assert keychain.load_credential(TEST_USERNAME) is None
    finally:
        keychain.delete_credential(TEST_USERNAME)  # don't leave test secrets in the real Keychain


def test_delete_credential_is_idempotent():
    keychain.delete_credential(TEST_USERNAME)
    keychain.delete_credential(TEST_USERNAME)  # must not raise on an already-absent credential


def test_remembered_username_roundtrip(tmp_path):
    data_dir = str(tmp_path)
    assert keychain.remembered_username(data_dir) is None

    keychain.set_remembered_username(data_dir, "alice")
    assert keychain.remembered_username(data_dir) == "alice"
    assert os.path.exists(os.path.join(data_dir, ".remembered_username"))

    keychain.set_remembered_username(data_dir, "bob")
    assert keychain.remembered_username(data_dir) == "bob"

    keychain.clear_remembered_username(data_dir)
    assert keychain.remembered_username(data_dir) is None


def test_clear_remembered_username_is_idempotent(tmp_path):
    data_dir = str(tmp_path)
    keychain.clear_remembered_username(data_dir)  # must not raise when nothing was ever set
