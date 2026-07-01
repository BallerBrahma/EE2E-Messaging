"""Identity keys, signed prekeys and one-time prekeys.

Mirrors the key material described in the Signal X3DH spec:
https://signal.org/docs/specifications/x3dh/

- Identity key: long-term X25519 (for DH) + Ed25519 (for signing).
- Signed prekey: medium-term X25519 key, signed by the Ed25519 identity key.
- One-time prekeys: a batch of single-use X25519 keys, consumed by the
  server on first use by a peer.
"""
from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from crypto import primitives as prim


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass
class SignedPrekey:
    key_id: str
    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    signature: bytes  # Ed25519 signature over public_key bytes, by identity key


@dataclass
class OneTimePrekey:
    key_id: str
    private_key: X25519PrivateKey
    public_key: X25519PublicKey


@dataclass
class PrekeyBundle:
    """Public material as published to / fetched from the server."""
    identity_pub_dh: bytes
    identity_pub_sign: bytes
    signed_prekey_id: str
    signed_prekey_pub: bytes
    signed_prekey_sig: bytes
    one_time_prekey_id: str | None
    one_time_prekey_pub: bytes | None

    def to_json(self) -> dict:
        return {
            "identity_pub_dh": _b64(self.identity_pub_dh),
            "identity_pub_sign": _b64(self.identity_pub_sign),
            "signed_prekey_id": self.signed_prekey_id,
            "signed_prekey_pub": _b64(self.signed_prekey_pub),
            "signed_prekey_sig": _b64(self.signed_prekey_sig),
            "one_time_prekey_id": self.one_time_prekey_id,
            "one_time_prekey_pub": _b64(self.one_time_prekey_pub) if self.one_time_prekey_pub else None,
        }

    @staticmethod
    def from_json(data: dict) -> "PrekeyBundle":
        return PrekeyBundle(
            identity_pub_dh=_unb64(data["identity_pub_dh"]),
            identity_pub_sign=_unb64(data["identity_pub_sign"]),
            signed_prekey_id=data["signed_prekey_id"],
            signed_prekey_pub=_unb64(data["signed_prekey_pub"]),
            signed_prekey_sig=_unb64(data["signed_prekey_sig"]),
            one_time_prekey_id=data.get("one_time_prekey_id"),
            one_time_prekey_pub=_unb64(data["one_time_prekey_pub"]) if data.get("one_time_prekey_pub") else None,
        )

    def verify_signed_prekey(self) -> bool:
        identity_sign_pub = prim.ed25519_pub_from_bytes(self.identity_pub_sign)
        return prim.ed25519_verify(identity_sign_pub, self.signed_prekey_sig, self.signed_prekey_pub)


def new_key_id() -> str:
    return secrets.token_hex(8)


def generate_signed_prekey(identity_sign_priv: Ed25519PrivateKey) -> SignedPrekey:
    priv = prim.x25519_generate()
    pub = priv.public_key()
    pub_bytes = prim.x25519_pub_bytes(pub)
    sig = prim.ed25519_sign(identity_sign_priv, pub_bytes)
    return SignedPrekey(key_id=new_key_id(), private_key=priv, public_key=pub, signature=sig)


def generate_one_time_prekeys(count: int) -> list[OneTimePrekey]:
    out = []
    for _ in range(count):
        priv = prim.x25519_generate()
        out.append(OneTimePrekey(key_id=new_key_id(), private_key=priv, public_key=priv.public_key()))
    return out


@dataclass
class KeyStore:
    """All private key material for the local user.

    This is the object that gets serialized to an encrypted blob on disk
    (see client/storage.py) and never leaves the device unencrypted.
    """
    username: str
    identity_priv_dh: X25519PrivateKey
    identity_priv_sign: Ed25519PrivateKey
    signed_prekey: SignedPrekey
    one_time_prekeys: dict[str, OneTimePrekey] = field(default_factory=dict)

    @staticmethod
    def generate(username: str, one_time_prekey_count: int = 20) -> "KeyStore":
        identity_priv_dh = prim.x25519_generate()
        identity_priv_sign = prim.ed25519_generate()
        signed_prekey = generate_signed_prekey(identity_priv_sign)
        otks = generate_one_time_prekeys(one_time_prekey_count)
        return KeyStore(
            username=username,
            identity_priv_dh=identity_priv_dh,
            identity_priv_sign=identity_priv_sign,
            signed_prekey=signed_prekey,
            one_time_prekeys={k.key_id: k for k in otks},
        )

    def identity_pub_dh_bytes(self) -> bytes:
        return prim.x25519_pub_bytes(self.identity_priv_dh.public_key())

    def identity_pub_sign_bytes(self) -> bytes:
        return prim.ed25519_pub_bytes(self.identity_priv_sign.public_key())

    def public_bundle(self, include_one_time: bool = True) -> PrekeyBundle:
        otk_id, otk_pub = None, None
        if include_one_time and self.one_time_prekeys:
            otk = next(iter(self.one_time_prekeys.values()))
            otk_id, otk_pub = otk.key_id, prim.x25519_pub_bytes(otk.public_key)
        return PrekeyBundle(
            identity_pub_dh=self.identity_pub_dh_bytes(),
            identity_pub_sign=self.identity_pub_sign_bytes(),
            signed_prekey_id=self.signed_prekey.key_id,
            signed_prekey_pub=prim.x25519_pub_bytes(self.signed_prekey.public_key),
            signed_prekey_sig=self.signed_prekey.signature,
            one_time_prekey_id=otk_id,
            one_time_prekey_pub=otk_pub,
        )

    def top_up_one_time_prekeys(self, target_count: int = 20) -> list[OneTimePrekey]:
        """Generate new one-time prekeys if the local pool is running low."""
        needed = target_count - len(self.one_time_prekeys)
        if needed <= 0:
            return []
        new_keys = generate_one_time_prekeys(needed)
        for k in new_keys:
            self.one_time_prekeys[k.key_id] = k
        return new_keys

    # -- serialization -----------------------------------------------------

    def to_json(self) -> dict:
        return {
            "username": self.username,
            "identity_priv_dh": _b64(prim.x25519_priv_bytes(self.identity_priv_dh)),
            "identity_priv_sign": _b64(prim.ed25519_priv_bytes(self.identity_priv_sign)),
            "signed_prekey": {
                "key_id": self.signed_prekey.key_id,
                "private_key": _b64(prim.x25519_priv_bytes(self.signed_prekey.private_key)),
                "signature": _b64(self.signed_prekey.signature),
            },
            "one_time_prekeys": {
                k: _b64(prim.x25519_priv_bytes(v.private_key))
                for k, v in self.one_time_prekeys.items()
            },
        }

    @staticmethod
    def from_json(data: dict) -> "KeyStore":
        identity_priv_dh = prim.x25519_priv_from_bytes(_unb64(data["identity_priv_dh"]))
        identity_priv_sign = prim.ed25519_priv_from_bytes(_unb64(data["identity_priv_sign"]))
        sp = data["signed_prekey"]
        sp_priv = prim.x25519_priv_from_bytes(_unb64(sp["private_key"]))
        signed_prekey = SignedPrekey(
            key_id=sp["key_id"],
            private_key=sp_priv,
            public_key=sp_priv.public_key(),
            signature=_unb64(sp["signature"]),
        )
        otks = {}
        for key_id, priv_b64 in data["one_time_prekeys"].items():
            priv = prim.x25519_priv_from_bytes(_unb64(priv_b64))
            otks[key_id] = OneTimePrekey(key_id=key_id, private_key=priv, public_key=priv.public_key())
        return KeyStore(
            username=data["username"],
            identity_priv_dh=identity_priv_dh,
            identity_priv_sign=identity_priv_sign,
            signed_prekey=signed_prekey,
            one_time_prekeys=otks,
        )

    def encrypt(self, password: str) -> bytes:
        """Serialize + encrypt this keystore for storage on disk."""
        salt = prim.new_salt()
        key = prim.derive_key_from_password(password, salt)
        plaintext = json.dumps(self.to_json()).encode("utf-8")
        blob = prim.aead_encrypt(key, plaintext)
        return salt + blob

    @staticmethod
    def decrypt(data: bytes, password: str) -> "KeyStore":
        salt, blob = data[:prim.SCRYPT_SALT_LEN], data[prim.SCRYPT_SALT_LEN:]
        key = prim.derive_key_from_password(password, salt)
        plaintext = prim.aead_decrypt(key, blob)
        return KeyStore.from_json(json.loads(plaintext.decode("utf-8")))
