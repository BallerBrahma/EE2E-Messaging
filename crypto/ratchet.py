"""Double Ratchet algorithm.

Implements https://signal.org/docs/specifications/doubleratchet/ on top of
X25519 (DH ratchet) + HKDF/HMAC-SHA256 (KDF chains) + AES-256-GCM (message
encryption). Provides forward secrecy (old message keys can't decrypt new
messages and vice versa) and post-compromise security (a compromised chain
key heals itself after the next DH ratchet step), plus out-of-order message
handling via a skipped-message-key cache.
"""
from __future__ import annotations

import base64
import hmac
import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from crypto import primitives as prim

MAX_SKIP = 1000
ROOT_INFO = b"E2EE-ratchet-root-v1"
MSG_KEY_CONST = b"\x01"
CHAIN_KEY_CONST = b"\x02"


class RatchetError(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def kdf_rk(root_key: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    out = prim.hkdf(dh_out, 64, salt=root_key, info=ROOT_INFO)
    return out[:32], out[32:]


def kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    next_chain_key = hmac.new(chain_key, CHAIN_KEY_CONST, hashlib.sha256).digest()
    message_key = hmac.new(chain_key, MSG_KEY_CONST, hashlib.sha256).digest()
    return next_chain_key, message_key


@dataclass
class MessageHeader:
    dh_pub: bytes
    pn: int
    n: int

    def to_bytes(self) -> bytes:
        # Used as AEAD associated data -- bind header fields to the ciphertext.
        return self.dh_pub + self.pn.to_bytes(4, "big") + self.n.to_bytes(4, "big")

    def to_json(self) -> dict:
        return {"dh_pub": _b64(self.dh_pub), "pn": self.pn, "n": self.n}

    @staticmethod
    def from_json(data: dict) -> "MessageHeader":
        return MessageHeader(dh_pub=_unb64(data["dh_pub"]), pn=data["pn"], n=data["n"])


@dataclass
class RatchetMessage:
    header: MessageHeader
    ciphertext: bytes

    def to_json(self) -> dict:
        return {"header": self.header.to_json(), "ciphertext": _b64(self.ciphertext)}

    @staticmethod
    def from_json(data: dict) -> "RatchetMessage":
        return RatchetMessage(header=MessageHeader.from_json(data["header"]), ciphertext=_unb64(data["ciphertext"]))


@dataclass
class RatchetState:
    dhs_priv: X25519PrivateKey
    dhr_pub: bytes | None
    root_key: bytes
    chain_key_send: bytes | None
    chain_key_recv: bytes | None
    n_send: int = 0
    n_recv: int = 0
    prev_chain_len: int = 0
    skipped: dict[tuple[bytes, int], bytes] = field(default_factory=dict)
    associated_data: bytes = b""

    # -- initialization -----------------------------------------------------

    @staticmethod
    def init_as_initiator(shared_secret: bytes, associated_data: bytes, remote_ratchet_pub: bytes) -> "RatchetState":
        """Alice's side, called right after crypto.x3dh.initiate()."""
        dhs_priv = prim.x25519_generate()
        dhr_pub_key = prim.x25519_pub_from_bytes(remote_ratchet_pub)
        dh_out = prim.x25519_dh(dhs_priv, dhr_pub_key)
        root_key, chain_key_send = kdf_rk(shared_secret, dh_out)
        return RatchetState(
            dhs_priv=dhs_priv,
            dhr_pub=remote_ratchet_pub,
            root_key=root_key,
            chain_key_send=chain_key_send,
            chain_key_recv=None,
            associated_data=associated_data,
        )

    @staticmethod
    def init_as_responder(shared_secret: bytes, associated_data: bytes, own_ratchet_priv: X25519PrivateKey) -> "RatchetState":
        """Bob's side. own_ratchet_priv is his signed-prekey private key,
        which doubled as the initial ratchet keypair Alice used in X3DH."""
        return RatchetState(
            dhs_priv=own_ratchet_priv,
            dhr_pub=None,
            root_key=shared_secret,
            chain_key_send=None,
            chain_key_recv=None,
            associated_data=associated_data,
        )

    # -- encrypt / decrypt ---------------------------------------------------

    def encrypt(self, plaintext: bytes) -> RatchetMessage:
        if self.chain_key_send is None:
            raise RatchetError("no sending chain established yet (responder must receive first)")
        self.chain_key_send, message_key = kdf_ck(self.chain_key_send)
        header = MessageHeader(
            dh_pub=prim.x25519_pub_bytes(self.dhs_priv.public_key()),
            pn=self.prev_chain_len,
            n=self.n_send,
        )
        self.n_send += 1
        ct = prim.aead_encrypt(message_key, plaintext, self.associated_data + header.to_bytes())
        return RatchetMessage(header=header, ciphertext=ct)

    def decrypt(self, message: RatchetMessage) -> bytes:
        skip_key = (message.header.dh_pub, message.header.n)
        if skip_key in self.skipped:
            message_key = self.skipped.pop(skip_key)
            return prim.aead_decrypt(message_key, message.ciphertext, self.associated_data + message.header.to_bytes())

        if message.header.dh_pub != self.dhr_pub:
            self._skip_message_keys(message.header.pn)
            self._dh_ratchet(message.header.dh_pub)

        self._skip_message_keys(message.header.n)
        self.chain_key_recv, message_key = kdf_ck(self.chain_key_recv)
        self.n_recv += 1
        return prim.aead_decrypt(message_key, message.ciphertext, self.associated_data + message.header.to_bytes())

    # -- internals ------------------------------------------------------------

    def _skip_message_keys(self, until: int) -> None:
        if self.chain_key_recv is None:
            return
        if until - self.n_recv > MAX_SKIP:
            raise RatchetError("too many skipped messages -- refusing (possible DoS)")
        while self.n_recv < until:
            self.chain_key_recv, message_key = kdf_ck(self.chain_key_recv)
            self.skipped[(self.dhr_pub, self.n_recv)] = message_key
            self.n_recv += 1

    def _dh_ratchet(self, new_dhr_pub: bytes) -> None:
        self.prev_chain_len = self.n_send
        self.n_send = 0
        self.n_recv = 0
        self.dhr_pub = new_dhr_pub

        dh_out = prim.x25519_dh(self.dhs_priv, prim.x25519_pub_from_bytes(self.dhr_pub))
        self.root_key, self.chain_key_recv = kdf_rk(self.root_key, dh_out)

        self.dhs_priv = prim.x25519_generate()
        dh_out = prim.x25519_dh(self.dhs_priv, prim.x25519_pub_from_bytes(self.dhr_pub))
        self.root_key, self.chain_key_send = kdf_rk(self.root_key, dh_out)

    # -- serialization ---------------------------------------------------------

    def to_json(self) -> dict:
        return {
            "dhs_priv": _b64(prim.x25519_priv_bytes(self.dhs_priv)),
            "dhr_pub": _b64(self.dhr_pub) if self.dhr_pub else None,
            "root_key": _b64(self.root_key),
            "chain_key_send": _b64(self.chain_key_send) if self.chain_key_send else None,
            "chain_key_recv": _b64(self.chain_key_recv) if self.chain_key_recv else None,
            "n_send": self.n_send,
            "n_recv": self.n_recv,
            "prev_chain_len": self.prev_chain_len,
            "skipped": [
                {"dh_pub": _b64(dh), "n": n, "mk": _b64(mk)}
                for (dh, n), mk in self.skipped.items()
            ],
            "associated_data": _b64(self.associated_data),
        }

    @staticmethod
    def from_json(data: dict) -> "RatchetState":
        skipped = {
            (_unb64(item["dh_pub"]), item["n"]): _unb64(item["mk"])
            for item in data["skipped"]
        }
        return RatchetState(
            dhs_priv=prim.x25519_priv_from_bytes(_unb64(data["dhs_priv"])),
            dhr_pub=_unb64(data["dhr_pub"]) if data["dhr_pub"] else None,
            root_key=_unb64(data["root_key"]),
            chain_key_send=_unb64(data["chain_key_send"]) if data["chain_key_send"] else None,
            chain_key_recv=_unb64(data["chain_key_recv"]) if data["chain_key_recv"] else None,
            n_send=data["n_send"],
            n_recv=data["n_recv"],
            prev_chain_len=data["prev_chain_len"],
            skipped=skipped,
            associated_data=_unb64(data["associated_data"]),
        )
