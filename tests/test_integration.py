"""End-to-end tests: real relay server (in-process) + headless clients
talking over real websockets. Covers the X3DH handshake + Double Ratchet
flow (including offline delivery), the envelope-based features built on top
of it (group fan-out, delete-for-everyone, attachments), and server-side
presence broadcast/snapshot.
"""
from __future__ import annotations

import asyncio
import base64
import os

import pytest

from client.network import NetworkClient
from client.session_manager import SessionManager
from client.storage import LocalStorage, group_conversation_id
from server.server import run_server


async def _make_client(uri: str, tmp_dir: str, username: str, password: str) -> SessionManager:
    storage = LocalStorage(os.path.join(tmp_dir, f"{username}.sqlite3"))
    keystore, _recovery_phrase = storage.create_identity(username, password)
    network = NetworkClient(uri)
    await network.connect()
    await network.register(username, password)
    await network.login(username, password)
    session_manager = SessionManager(keystore, storage, network)
    await session_manager.publish_keys()
    return session_manager


async def _capture(owner: SessionManager, incoming, out_list):
    out_list.append(owner.handle_incoming(incoming))


def _listen(session_manager: SessionManager, out_list: list) -> None:
    session_manager.network.on_message = lambda incoming: _capture(session_manager, incoming, out_list)


@pytest.mark.asyncio
async def test_two_clients_exchange_messages_through_real_server(tmp_path):
    port = 8971
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server.sqlite3")))
    await asyncio.sleep(0.2)  # let the server start listening
    try:
        alice = await _make_client(uri, str(tmp_path), "alice", "correct horse battery staple")
        bob = await _make_client(uri, str(tmp_path), "bob", "another very good passphrase")

        received: list = []
        _listen(bob, received)

        await alice.send_text("bob", "hello bob, this is alice")
        await asyncio.sleep(0.2)

        assert len(received) == 1
        assert received[0].kind == "message"
        assert received[0].sender == "alice"
        assert received[0].body["content"] == "hello bob, this is alice"

        _listen(alice, received)
        await bob.send_text("alice", "hi alice, got your message")
        await asyncio.sleep(0.2)

        assert len(received) == 2
        assert received[1].sender == "bob"
        assert received[1].body["content"] == "hi alice, got your message"

        assert [m.body["content"] for m in alice.history("bob")] == [
            "hello bob, this is alice",
            "hi alice, got your message",
        ]
    finally:
        server_task.cancel()


@pytest.mark.asyncio
async def test_offline_message_delivered_on_next_login(tmp_path):
    port = 8972
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server2.sqlite3")))
    await asyncio.sleep(0.2)
    try:
        alice = await _make_client(uri, str(tmp_path), "alice2", "correct horse battery staple 2")

        bob_storage = LocalStorage(os.path.join(str(tmp_path), "bob2.sqlite3"))
        bob_keystore, _bob_recovery_phrase = bob_storage.create_identity("bob2", "another very good passphrase 2")
        bob_network = NetworkClient(uri)
        await bob_network.connect()
        await bob_network.register("bob2", "another very good passphrase 2")
        await bob_network.login("bob2", "another very good passphrase 2")
        bob_session = SessionManager(bob_keystore, bob_storage, bob_network)
        await bob_session.publish_keys()

        # bob goes offline
        await bob_network.close()

        # alice sends while bob is offline -- server must queue it
        await alice.send_text("bob2", "are you there?")
        await asyncio.sleep(0.2)

        # bob logs back in on a fresh connection -- pending mailbox should be pushed
        bob_network2 = NetworkClient(uri)
        await bob_network2.connect()
        received = []
        bob_session.network = bob_network2
        _listen(bob_session, received)
        await bob_network2.login("bob2", "another very good passphrase 2")
        await asyncio.sleep(0.2)

        assert len(received) == 1
        assert received[0].body["content"] == "are you there?"
    finally:
        server_task.cancel()


@pytest.mark.asyncio
async def test_group_chat_fanout_delivers_to_all_members(tmp_path):
    port = 8973
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server3.sqlite3")))
    await asyncio.sleep(0.2)
    try:
        alice = await _make_client(uri, str(tmp_path), "alice3", "correct horse battery staple 3")
        bob = await _make_client(uri, str(tmp_path), "bob3", "another very good passphrase 3")
        carol = await _make_client(uri, str(tmp_path), "carol3", "yet another good passphrase 3")

        bob_events, carol_events = [], []
        _listen(bob, bob_events)
        _listen(carol, carol_events)

        group_id = await alice.create_group("Trio", ["bob3", "carol3"])
        await asyncio.sleep(0.3)

        assert bob_events[-1].kind == "group_invite"
        assert carol_events[-1].kind == "group_invite"
        assert set(bob.storage.group_members(group_id)) == {"alice3", "bob3", "carol3"}
        assert set(carol.storage.group_members(group_id)) == {"alice3", "bob3", "carol3"}

        conversation_id = group_conversation_id(group_id)
        message_id = await alice.send_text(conversation_id, "hello group")
        await asyncio.sleep(0.3)

        bob_msg = next(e for e in bob_events if e.kind == "message")
        carol_msg = next(e for e in carol_events if e.kind == "message")
        assert bob_msg.message_id == carol_msg.message_id == message_id
        assert bob_msg.sender == carol_msg.sender == "alice3"
        assert bob_msg.body["content"] == carol_msg.body["content"] == "hello group"
        assert [m.body["content"] for m in alice.history(conversation_id)][-1] == "hello group"
    finally:
        server_task.cancel()


@pytest.mark.asyncio
async def test_delete_for_everyone(tmp_path):
    port = 8974
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server4.sqlite3")))
    await asyncio.sleep(0.2)
    try:
        alice = await _make_client(uri, str(tmp_path), "alice4", "correct horse battery staple 4")
        bob = await _make_client(uri, str(tmp_path), "bob4", "another very good passphrase 4")

        bob_events: list = []
        _listen(bob, bob_events)

        message_id = await alice.send_text("bob4", "oops wrong message")
        await asyncio.sleep(0.2)
        assert any(m.message_id == message_id for m in bob.history("alice4"))

        await alice.delete_message("bob4", message_id)
        await asyncio.sleep(0.2)

        assert bob_events[-1].kind == "delete"
        assert bob_events[-1].message_id == message_id
        assert not any(m.message_id == message_id for m in alice.history("bob4"))
        assert not any(m.message_id == message_id for m in bob.history("alice4"))
    finally:
        server_task.cancel()


@pytest.mark.asyncio
async def test_presence_broadcast_and_snapshot(tmp_path):
    port = 8975
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server5.sqlite3")))
    await asyncio.sleep(0.2)
    try:
        # bob is already online before alice connects.
        bob = await _make_client(uri, str(tmp_path), "bob5", "another very good passphrase 5")
        presence_events: list = []

        async def _capture_presence(username, online):
            presence_events.append((username, online))

        bob.network.on_presence = _capture_presence

        alice_storage = LocalStorage(os.path.join(str(tmp_path), "alice5.sqlite3"))
        alice_storage.create_identity("alice5", "correct horse battery staple 5")
        alice_network = NetworkClient(uri)
        await alice_network.connect()
        await alice_network.register("alice5", "correct horse battery staple 5")

        # alice logs in after bob -- bob should see a live "online" presence event.
        await alice_network.login("alice5", "correct horse battery staple 5")
        await asyncio.sleep(0.2)
        assert ("alice5", True) in presence_events

        # carol logs in while alice is online -- her snapshot should list alice5.
        carol_storage = LocalStorage(os.path.join(str(tmp_path), "carol5.sqlite3"))
        carol_storage.create_identity("carol5", "yet another good passphrase 5")
        carol_network = NetworkClient(uri)
        await carol_network.connect()
        await carol_network.register("carol5", "yet another good passphrase 5")
        snapshots: list = []

        async def _capture_snapshot(usernames):
            snapshots.append(usernames)

        carol_network.on_presence_snapshot = _capture_snapshot
        await carol_network.login("carol5", "yet another good passphrase 5")
        await asyncio.sleep(0.2)
        assert snapshots and "alice5" in snapshots[0] and "bob5" in snapshots[0]

        # alice disconnects -- bob should be told she's offline.
        await alice_network.close()
        await asyncio.sleep(0.2)
        assert ("alice5", False) in presence_events
    finally:
        server_task.cancel()


@pytest.mark.asyncio
async def test_attachment_round_trips_byte_for_byte(tmp_path):
    port = 8976
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server6.sqlite3")))
    await asyncio.sleep(0.2)
    try:
        alice = await _make_client(uri, str(tmp_path), "alice6", "correct horse battery staple 6")
        bob = await _make_client(uri, str(tmp_path), "bob6", "another very good passphrase 6")

        bob_events: list = []
        _listen(bob, bob_events)

        original_bytes = b"these are the bytes of a small text file, encrypted end to end\x00\x01\x02"
        message_id = await alice.send_attachment("bob6", "notes.txt", "text/plain", original_bytes)
        await asyncio.sleep(0.3)

        event = next(e for e in bob_events if e.kind == "message")
        assert event.message_kind == "attachment"
        assert event.message_id == message_id
        assert event.body["filename"] == "notes.txt"
        assert base64.b64decode(event.body["data_b64"]) == original_bytes

        stored = next(m for m in bob.history("alice6") if m.message_id == message_id)
        assert base64.b64decode(stored.body["data_b64"]) == original_bytes
    finally:
        server_task.cancel()


@pytest.mark.asyncio
async def test_dynamic_group_membership_add_and_remove(tmp_path):
    port = 8977
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server7.sqlite3")))
    await asyncio.sleep(0.2)
    try:
        alice = await _make_client(uri, str(tmp_path), "alice7", "correct horse battery staple 7")
        bob = await _make_client(uri, str(tmp_path), "bob7", "another very good passphrase 7")
        carol = await _make_client(uri, str(tmp_path), "carol7", "yet another good passphrase 7")

        bob_events, carol_events = [], []
        _listen(bob, bob_events)
        _listen(carol, carol_events)

        group_id = await alice.create_group("Pair", ["bob7"])
        conversation_id = group_conversation_id(group_id)
        await asyncio.sleep(0.2)
        assert set(bob.storage.group_members(group_id)) == {"alice7", "bob7"}

        # add carol -- she should get a full invite, bob should be told she was added
        await alice.add_group_member(group_id, "carol7")
        await asyncio.sleep(0.3)

        assert carol_events[-1].kind == "group_invite"
        assert set(carol.storage.group_members(group_id)) == {"alice7", "bob7", "carol7"}
        assert bob_events[-1].kind == "group_member_added"
        assert bob_events[-1].body["added_username"] == "carol7"
        assert set(bob.storage.group_members(group_id)) == {"alice7", "bob7", "carol7"}

        await alice.send_text(conversation_id, "hi everyone")
        await asyncio.sleep(0.3)
        assert any(e.kind == "message" and e.body.get("content") == "hi everyone" for e in bob_events)
        assert any(e.kind == "message" and e.body.get("content") == "hi everyone" for e in carol_events)

        # remove bob -- he and carol should both be informed, bob loses membership
        await alice.remove_group_member(group_id, "bob7")
        await asyncio.sleep(0.3)

        assert bob_events[-1].kind == "group_member_removed"
        assert bob_events[-1].body["removed_username"] == "bob7"
        assert carol_events[-1].kind == "group_member_removed"
        assert "bob7" not in bob.storage.group_members(group_id)
        assert "bob7" not in carol.storage.group_members(group_id)

        # bob can no longer send to (or be reached via) the group
        with pytest.raises(ValueError):
            await bob.send_text(conversation_id, "can I still talk?")

        bob_message_count_before = sum(1 for e in bob_events if e.kind == "message")
        await alice.send_text(conversation_id, "just us now")
        await asyncio.sleep(0.3)
        assert any(e.kind == "message" and e.body.get("content") == "just us now" for e in carol_events)
        assert sum(1 for e in bob_events if e.kind == "message") == bob_message_count_before
    finally:
        server_task.cancel()


@pytest.mark.asyncio
async def test_profile_picture_fans_out_to_contacts_and_group_members(tmp_path):
    port = 8978
    uri = f"ws://localhost:{port}"
    server_task = asyncio.create_task(run_server("localhost", port, os.path.join(str(tmp_path), "server8.sqlite3")))
    await asyncio.sleep(0.2)
    try:
        alice = await _make_client(uri, str(tmp_path), "alice8", "correct horse battery staple 8")
        bob = await _make_client(uri, str(tmp_path), "bob8", "another very good passphrase 8")
        carol = await _make_client(uri, str(tmp_path), "carol8", "yet another good passphrase 8")

        bob_events, carol_events = [], []
        _listen(bob, bob_events)
        _listen(carol, carol_events)

        # establish alice<->bob as a direct contact, and alice<->carol via a group
        await alice.send_text("bob8", "hi bob")
        await alice.create_group("Duo", ["carol8"])
        await asyncio.sleep(0.3)

        image_bytes = b"\x89PNG\r\n\x1a\nnot a real png but stands in for one \x00\x01\x02"
        await alice.set_profile_picture(image_bytes, "image/png")
        await asyncio.sleep(0.3)

        assert bob_events[-1].kind == "avatar_update"
        assert carol_events[-1].kind == "avatar_update"
        assert alice.avatar("alice8") == image_bytes
        assert bob.avatar("alice8") == image_bytes
        assert carol.avatar("alice8") == image_bytes
    finally:
        server_task.cancel()
