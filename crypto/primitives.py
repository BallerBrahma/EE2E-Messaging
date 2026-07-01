"""Low-level cryptographic building blocks.

Everything here is a thin wrapper around `cryptography` primitives.
No custom cryptography is implemented in this module or anywhere else
in this project -- only well-known algorithms from an audited library.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

AEAD_KEY_LEN = 32  # AES-256-GCM
AEAD_NONCE_LEN = 12
X25519_KEY_LEN = 32
ED25519_KEY_LEN = 32
SCRYPT_SALT_LEN = 16


class DecryptionError(Exception):
    """Raised when an AEAD ciphertext fails to authenticate/decrypt."""


# --------------------------------------------------------------------------
# AEAD (AES-256-GCM)
# --------------------------------------------------------------------------

def aead_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce || ciphertext(+tag)."""
    nonce = os.urandom(AEAD_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def aead_decrypt(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt a nonce||ciphertext blob produced by aead_encrypt."""
    if len(blob) < AEAD_NONCE_LEN:
        raise DecryptionError("ciphertext too short")
    nonce, ct = blob[:AEAD_NONCE_LEN], blob[AEAD_NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ct, associated_data)
    except Exception as exc:  # cryptography raises InvalidTag
        raise DecryptionError("authentication failed") from exc


# --------------------------------------------------------------------------
# HKDF
# --------------------------------------------------------------------------

def hkdf(input_key_material: bytes, length: int, salt: bytes | None, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(input_key_material)


def hkdf_multi(input_key_material: bytes, length: int, salt: bytes | None, info: bytes, n: int) -> list[bytes]:
    """Derive n*length bytes and split into n chunks (used for ratchet KDFs)."""
    out = hkdf(input_key_material, length * n, salt, info)
    return [out[i * length:(i + 1) * length] for i in range(n)]


# --------------------------------------------------------------------------
# Password-based key derivation (Scrypt) -- used for the local keystore
# --------------------------------------------------------------------------

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=AEAD_KEY_LEN, n=2 ** 15, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def new_salt() -> bytes:
    return os.urandom(SCRYPT_SALT_LEN)


# --------------------------------------------------------------------------
# X25519 (DH) helpers
# --------------------------------------------------------------------------

def x25519_generate() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def x25519_pub_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def x25519_pub_from_bytes(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


def x25519_priv_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def x25519_priv_from_bytes(data: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(data)


def x25519_dh(private_key: X25519PrivateKey, public_key: X25519PublicKey) -> bytes:
    return private_key.exchange(public_key)


# --------------------------------------------------------------------------
# Ed25519 (signing) helpers
# --------------------------------------------------------------------------

def ed25519_generate() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def ed25519_pub_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed25519_pub_from_bytes(data: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(data)


def ed25519_priv_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def ed25519_priv_from_bytes(data: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(data)


def ed25519_sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def ed25519_verify(public_key: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
