"""pywebview JS bridge: exposes session_manager/storage/network to the React
frontend as `window.pywebview.api.*` calls, and pushes async server events
(messages, presence, group/avatar changes) into JS via `window.evaluate_js`.

Runs a single persistent asyncio event loop on a background thread, since
pywebview invokes exposed methods synchronously from its own thread while
`NetworkClient`/`SessionManager` are all `async def`.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import threading
from dataclasses import asdict

from client import keychain, spellcheck
from client.network import IncomingMessage, NetworkClient
from client.session_manager import IncomingEvent, SessionManager
from client.storage import InvalidRecoveryPhrase, LocalStorage, WrongPassword

DATA_DIR = os.path.join(os.path.expanduser("~"), ".e2ee_client")


def _storage_path(username: str) -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    safe = "".join(c for c in username if c.isalnum() or c in ("-", "_")) or "user"
    return os.path.join(DATA_DIR, f"{safe}.sqlite3")


def _event_to_json(event: IncomingEvent) -> dict:
    return {
        "type": event.kind,
        "conversation_id": event.conversation_id,
        "sender": event.sender,
        "timestamp": event.timestamp,
        "message_id": event.message_id,
        "message_kind": event.message_kind,
        "body": event.body,
    }


class Api:
    """Instantiated once and passed as `js_api=` to `webview.create_window`.
    `window` is assigned by main_client_web.py after the webview window is
    created (needed here so push-event handlers can call `evaluate_js`)."""

    def __init__(self):
        self.window = None
        self.session_manager: SessionManager | None = None
        self.storage: LocalStorage | None = None
        self._online_usernames: set[str] = set()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=30)

    def _emit(self, event: dict) -> None:
        if self.window is not None:
            self.window.evaluate_js(f"window.__onBackendEvent && window.__onBackendEvent({json.dumps(event)})")

    # -- account ------------------------------------------------------------------------

    def has_local_identity(self, username: str) -> bool:
        return os.path.exists(_storage_path(username))

    def register(self, server: str, username: str, password: str) -> dict:
        return self._run_coro(self._async_register(server, username, password))

    async def _async_register(self, server: str, username: str, password: str) -> dict:
        storage = LocalStorage(_storage_path(username))
        keystore, recovery_phrase = storage.create_identity(username, password)
        server_auth_token = storage.server_auth_token()
        network = await self._connect_and_attach(server, keystore, storage)
        await network.register(username, server_auth_token)  # new account only -- login/recover never re-register
        await network.login(username, server_auth_token)
        await self.session_manager.publish_keys()
        return {"username": username, "recovery_phrase": recovery_phrase}

    def login(self, server: str, username: str, password: str) -> dict:
        return self._run_coro(self._async_login(server, username, password))

    async def _async_login(self, server: str, username: str, password: str) -> dict:
        storage = LocalStorage(_storage_path(username))
        try:
            keystore, server_auth_token = storage.unlock(password)
        except WrongPassword as exc:
            raise Exception("incorrect password") from exc
        await self._bootstrap_login(server, username, server_auth_token, keystore, storage)
        return {"username": username}

    def recover_account(self, server: str, username: str, recovery_phrase: str, new_password: str) -> dict:
        return self._run_coro(self._async_recover_account(server, username, recovery_phrase, new_password))

    async def _async_recover_account(self, server: str, username: str, recovery_phrase: str, new_password: str) -> dict:
        storage = LocalStorage(_storage_path(username))
        try:
            keystore, server_auth_token = storage.unlock_with_recovery(recovery_phrase)
        except InvalidRecoveryPhrase as exc:
            raise Exception(str(exc)) from exc
        storage.rotate_password(new_password)  # existing server account is untouched -- the
        # server-auth token didn't change, so the relay login below just works with no
        # server-side coordination needed at all.
        await self._bootstrap_login(server, username, server_auth_token, keystore, storage)
        return {"username": username}

    async def _bootstrap_login(
        self, server: str, username: str, server_auth_token: str, keystore, storage: LocalStorage
    ) -> None:
        """Shared tail of login/recover_account for an *existing* server
        account: connect, log in with the server-auth token (never the
        human password -- see the client/storage.py module docstring),
        publish keys."""
        network = await self._connect_and_attach(server, keystore, storage)
        await network.login(username, server_auth_token)
        await self.session_manager.publish_keys()

    async def _connect_and_attach(self, server: str, keystore, storage: LocalStorage) -> NetworkClient:
        network = NetworkClient(server)
        session_manager = SessionManager(keystore, storage, network)
        self._attach_session(session_manager)  # wire push-event callbacks before connecting --
        # the server pushes presence_snapshot and any pending offline messages in the same
        # burst as the login response, so callbacks must already be set or those get dropped.
        await network.connect()
        return network

    def _attach_session(self, session_manager: SessionManager) -> None:
        self.session_manager = session_manager
        self.storage = session_manager.storage
        session_manager.network.on_message = self._on_message
        session_manager.network.on_presence = self._on_presence
        session_manager.network.on_presence_snapshot = self._on_presence_snapshot

    def current_username(self) -> str:
        return self.session_manager.username

    # -- remember me / Touch ID --------------------------------------------------------------

    def has_biometric_support(self) -> bool:
        return keychain.is_biometric_available()

    def get_remembered_username(self) -> str | None:
        return keychain.remembered_username(DATA_DIR)

    def remember_credentials(self, username: str, password: str) -> None:
        keychain.save_credential(username, password)
        keychain.set_remembered_username(DATA_DIR, username)

    def forget_remembered_login(self) -> None:
        username = keychain.remembered_username(DATA_DIR)
        if username:
            keychain.delete_credential(username)
        keychain.clear_remembered_username(DATA_DIR)

    def login_with_biometrics(self, server: str) -> dict:
        username = keychain.remembered_username(DATA_DIR)
        if not username:
            raise Exception("no remembered account -- log in manually and enable Touch ID first")
        if not keychain.authenticate_with_biometrics(f"Log in to Messages as {username}"):
            raise Exception("Touch ID authentication failed or was cancelled")
        password = keychain.load_credential(username)
        if password is None:
            raise Exception("no saved password found for this account -- log in manually")
        return self._run_coro(self._async_login(server, username, password))

    # -- push events (server -> frontend) ------------------------------------------------

    async def _on_message(self, incoming: IncomingMessage) -> None:
        try:
            event = self.session_manager.handle_incoming(incoming)
        except Exception as exc:
            self._emit({"type": "error", "message": f"failed to process message from {incoming.sender}: {exc}"})
            return
        self._emit(_event_to_json(event))

    async def _on_presence(self, username: str, online: bool) -> None:
        if online:
            self._online_usernames.add(username)
        else:
            self._online_usernames.discard(username)
        self._emit({"type": "presence", "username": username, "online": online})

    async def _on_presence_snapshot(self, online_usernames: list[str]) -> None:
        self._online_usernames = set(online_usernames)
        self._emit({"type": "presence_snapshot", "online_usernames": online_usernames})

    def online_usernames(self) -> list[str]:
        return sorted(self._online_usernames)

    # -- conversations / history ----------------------------------------------------------

    def list_conversations(self) -> list[dict]:
        return [asdict(c) for c in self.session_manager.conversations()]

    def get_history(self, conversation_id: str) -> list[dict]:
        return [asdict(m) for m in self.session_manager.history(conversation_id)]

    def contacts(self) -> list[str]:
        return self.session_manager.contacts()

    def group_members(self, group_id: str) -> list[str]:
        return self.storage.group_members(group_id)

    def group_name(self, group_id: str) -> str | None:
        return self.storage.group_name(group_id)

    def is_pinned(self, conversation_id: str) -> bool:
        return self.storage.is_pinned(conversation_id)

    def set_pinned(self, conversation_id: str, pinned: bool) -> None:
        self.session_manager.set_pinned(conversation_id, pinned)

    def add_contact(self, username: str) -> None:
        self.storage.add_contact(username)

    # -- sending ---------------------------------------------------------------------------

    def send_text(self, conversation_id: str, text: str) -> str:
        return self._run_coro(self.session_manager.send_text(conversation_id, text))

    def send_attachment(self, conversation_id: str, filename: str, mime: str, data_b64: str) -> str:
        data = base64.b64decode(data_b64)
        return self._run_coro(self.session_manager.send_attachment(conversation_id, filename, mime, data))

    def delete_message(self, conversation_id: str, message_id: str) -> None:
        self._run_coro(self.session_manager.delete_message(conversation_id, message_id))

    # -- groups -----------------------------------------------------------------------------

    def create_group(self, name: str, members: list[str]) -> str:
        return self._run_coro(self.session_manager.create_group(name, members))

    def add_group_member(self, group_id: str, username: str) -> None:
        self._run_coro(self.session_manager.add_group_member(group_id, username))

    def remove_group_member(self, group_id: str, username: str) -> None:
        self._run_coro(self.session_manager.remove_group_member(group_id, username))

    # -- avatars ----------------------------------------------------------------------------

    def get_avatar(self, username: str) -> str | None:
        data = self.session_manager.avatar(username)
        if data is None:
            return None
        return f"data:image/png;base64,{base64.b64encode(data).decode()}"

    def set_profile_picture(self, data_b64: str, mime: str) -> None:
        data = base64.b64decode(data_b64)
        self._run_coro(self.session_manager.set_profile_picture(data, mime))

    # -- spellcheck / autocorrect -----------------------------------------------------------

    def is_misspelled(self, word: str) -> bool:
        return spellcheck.is_misspelled(word)

    def spelling_suggestions(self, word: str) -> list[str]:
        return spellcheck.suggestions(word)

    def autocorrect_word(self, word: str) -> str | None:
        return spellcheck.autocorrect_word(word)

    # -- lifecycle --------------------------------------------------------------------------

    def close(self) -> None:
        if self.session_manager is not None:
            self._run_coro(self.session_manager.network.close())
