"""OS Keychain + Touch ID for "remember me" login.

The user's login password is also the Scrypt-derived encryption key for
their entire local message store (client/storage.py), so this deliberately
does NOT store it in plaintext anywhere (no localStorage, no plain file).
Storage goes through the OS Keychain via `keyring`; unlocking it is gated
by an actual Touch ID/device-passcode prompt via `LocalAuthentication`.

Security note (see README): the Touch ID check is an application-level
gate in front of a normal Keychain secret -- `authenticate_with_biometrics`
must return True before any caller reads the stored password -- rather than
a Keychain item with a hardware-enforced biometric ACL
(`kSecAccessControlBiometryCurrentSet`) bound directly to the secret. That
would need lower-level Security-framework calls; this is the pragmatic
middle ground for a personal-project convenience feature. It stops someone
who picks up an unlocked laptop from opening the app as you; it doesn't
stop a modified build of this app's own code from skipping the check.

Gracefully degrades to "not available" (rather than raising) when pyobjc's
LocalAuthentication isn't installed or the platform isn't macOS, so the
frontend can hide the biometric UI entirely and fall back to manual login.
"""
from __future__ import annotations

import os
import threading

import keyring
from keyring.errors import PasswordDeleteError

SERVICE_NAME = "ee2e-messenger"


def is_biometric_available() -> bool:
    try:
        from LocalAuthentication import LAContext, LAPolicyDeviceOwnerAuthenticationWithBiometrics
    except ImportError:
        return False
    try:
        context = LAContext.alloc().init()
        can_evaluate, _error = context.canEvaluatePolicy_error_(
            LAPolicyDeviceOwnerAuthenticationWithBiometrics, None
        )
        return bool(can_evaluate)
    except Exception:
        return False


def authenticate_with_biometrics(reason: str) -> bool:
    """Blocks until the user completes (or cancels/fails) the Touch ID
    prompt. Returns False on any error, timeout, or unsupported platform."""
    try:
        from LocalAuthentication import LAContext, LAPolicyDeviceOwnerAuthenticationWithBiometrics
    except ImportError:
        return False

    context = LAContext.alloc().init()
    result: dict[str, bool] = {"success": False}
    done = threading.Event()

    def reply(success, _error):
        result["success"] = bool(success)
        done.set()

    context.evaluatePolicy_localizedReason_reply_(LAPolicyDeviceOwnerAuthenticationWithBiometrics, reason, reply)
    done.wait(timeout=60)
    return result["success"]


def save_credential(username: str, password: str) -> None:
    keyring.set_password(SERVICE_NAME, username, password)


def load_credential(username: str) -> str | None:
    return keyring.get_password(SERVICE_NAME, username)


def delete_credential(username: str) -> None:
    try:
        keyring.delete_password(SERVICE_NAME, username)
    except PasswordDeleteError:
        pass  # already absent -- nothing to do


def _remembered_username_path(data_dir: str) -> str:
    return os.path.join(data_dir, ".remembered_username")


def remembered_username(data_dir: str) -> str | None:
    path = _remembered_username_path(data_dir)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        value = f.read().strip()
    return value or None


def set_remembered_username(data_dir: str, username: str) -> None:
    os.makedirs(data_dir, exist_ok=True)
    with open(_remembered_username_path(data_dir), "w", encoding="utf-8") as f:
        f.write(username)


def clear_remembered_username(data_dir: str) -> None:
    path = _remembered_username_path(data_dir)
    if os.path.exists(path):
        os.remove(path)
