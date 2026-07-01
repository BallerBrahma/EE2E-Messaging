"""Tests for the pywebview JS bridge (client/api.py), exercised directly
(no webview/JS involved) against a real relay server -- same in-process
real-server pattern as tests/test_integration.py."""
from __future__ import annotations

import asyncio
import os

import pytest

from client import keychain
from client.api import Api, _storage_path
from server.server import run_server


@pytest.mark.asyncio
async def test_register_login_and_send_receive(tmp_path, monkeypatch):
    monkeypatch.setattr("client.api.DATA_DIR", str(tmp_path))
    port = 8990
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server.sqlite3")))
    await asyncio.sleep(0.2)
    try:
        alice = Api()
        bob = Api()

        await asyncio.to_thread(alice.register, uri, "alice_api", "correct horse battery staple")
        await asyncio.to_thread(bob.register, uri, "bob_api", "another very good passphrase")
        assert alice.current_username() == "alice_api"

        events = []
        bob._emit = lambda event: events.append(event)  # bypass window.evaluate_js, capture directly

        alice.add_contact("bob_api")
        message_id = await asyncio.to_thread(alice.send_text, "bob_api", "hello from the bridge")
        await asyncio.sleep(0.3)

        assert any(e.get("type") == "message" and e.get("body", {}).get("content") == "hello from the bridge"
                   for e in events)
        history = alice.get_history("bob_api")
        assert any(m["message_id"] == message_id for m in history)

        convos = alice.list_conversations()
        assert any(c["conversation_id"] == "bob_api" for c in convos)
    finally:
        server_task.cancel()


@pytest.mark.asyncio
async def test_recover_account_after_forgotten_password(tmp_path, monkeypatch):
    monkeypatch.setattr("client.api.DATA_DIR", str(tmp_path))
    port = 8992
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server3.sqlite3")))
    await asyncio.sleep(0.2)
    try:
        alice = Api()
        bob = Api()
        result = await asyncio.to_thread(alice.register, uri, "alice_recover", "the original password")
        recovery_phrase = result["recovery_phrase"]
        await asyncio.to_thread(bob.register, uri, "bob_recover", "bob's password")

        alice.add_contact("bob_recover")
        message_id = await asyncio.to_thread(alice.send_text, "bob_recover", "message before recovery")
        await asyncio.to_thread(alice.close)
        await asyncio.to_thread(bob.close)

        # simulate "forgot password": fresh Api instance, wrong password fails...
        locked_out = Api()
        with pytest.raises(Exception):
            await asyncio.to_thread(locked_out.login, uri, "alice_recover", "wrong password")

        # ...but the recovery phrase + a new password gets back in.
        recovered = Api()
        recovered_result = await asyncio.to_thread(
            recovered.recover_account, uri, "alice_recover", recovery_phrase, "a brand new password"
        )
        assert recovered_result["username"] == "alice_recover"

        # message history survived the whole cycle
        history = recovered.get_history("bob_recover")
        assert any(m["message_id"] == message_id for m in history)

        # relay login now works with the new password too, with zero server-side coordination
        await asyncio.to_thread(recovered.close)
        relogged_in = Api()
        await asyncio.to_thread(relogged_in.login, uri, "alice_recover", "a brand new password")
        assert relogged_in.current_username() == "alice_recover"
    finally:
        server_task.cancel()


@pytest.mark.asyncio
async def test_group_create_and_pin(tmp_path, monkeypatch):
    monkeypatch.setattr("client.api.DATA_DIR", str(tmp_path))
    port = 8991
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server2.sqlite3")))
    await asyncio.sleep(0.2)
    try:
        alice = Api()
        bob = Api()
        await asyncio.to_thread(alice.register, uri, "alice_api2", "correct horse battery staple 2")
        await asyncio.to_thread(bob.register, uri, "bob_api2", "another very good passphrase 2")

        group_id = await asyncio.to_thread(alice.create_group, "Test Group", ["bob_api2"])
        assert alice.group_name(group_id) == "Test Group"
        assert set(alice.group_members(group_id)) == {"alice_api2", "bob_api2"}

        conversation_id = f"group:{group_id}"
        assert alice.is_pinned(conversation_id) is False
        alice.set_pinned(conversation_id, True)
        assert alice.is_pinned(conversation_id) is True
    finally:
        server_task.cancel()


def test_spellcheck_bridge_methods():
    api = Api()
    assert api.is_misspelled("helllo") is True
    assert api.is_misspelled("hello") is False
    assert api.autocorrect_word("whats") == "what's"
    assert "hello" in api.spelling_suggestions("helllo")


def test_storage_path_uses_data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("client.api.DATA_DIR", str(tmp_path))
    path = _storage_path("some user!")
    assert path.startswith(str(tmp_path))
    assert os.path.basename(path) == "someuser.sqlite3"


def test_remember_credentials_bridge(tmp_path, monkeypatch):
    monkeypatch.setattr("client.api.DATA_DIR", str(tmp_path))
    api = Api()
    test_username = "e2ee_test_api_remember_user"
    try:
        assert api.get_remembered_username() is None

        api.remember_credentials(test_username, "a test password")
        assert api.get_remembered_username() == test_username
        assert keychain.load_credential(test_username) == "a test password"

        api.forget_remembered_login()
        assert api.get_remembered_username() is None
        assert keychain.load_credential(test_username) is None
    finally:
        keychain.delete_credential(test_username)
