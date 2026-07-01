"""X3DH (Extended Triple Diffie-Hellman) initial key agreement.

Implements https://signal.org/docs/specifications/x3dh/ using X25519 for
the DH operations. This establishes a shared secret between two parties
who have never communicated before, using one side's published prekey
bundle -- the other side does not need to be online.
"""
from __future__ import annotations

from dataclasses import dataclass

from crypto import primitives as prim
from crypto.identity import KeyStore, PrekeyBundle

INFO = b"E2EE-X3DH-v1"
SHARED_SECRET_LEN = 32


class PrekeySignatureInvalid(Exception):
    pass


@dataclass
class InitialMessageHeader:
    """Metadata Alice sends to Bob so he can derive the same shared secret."""
    initiator_identity_pub_dh: bytes
    initiator_ephemeral_pub: bytes
    signed_prekey_id: str
    one_time_prekey_id: str | None

    def to_json(self) -> dict:
        import base64
        return {
            "initiator_identity_pub_dh": base64.b64encode(self.initiator_identity_pub_dh).decode(),
            "initiator_ephemeral_pub": base64.b64encode(self.initiator_ephemeral_pub).decode(),
            "signed_prekey_id": self.signed_prekey_id,
            "one_time_prekey_id": self.one_time_prekey_id,
        }

    @staticmethod
    def from_json(data: dict) -> "InitialMessageHeader":
        import base64
        return InitialMessageHeader(
            initiator_identity_pub_dh=base64.b64decode(data["initiator_identity_pub_dh"]),
            initiator_ephemeral_pub=base64.b64decode(data["initiator_ephemeral_pub"]),
            signed_prekey_id=data["signed_prekey_id"],
            one_time_prekey_id=data.get("one_time_prekey_id"),
        )


@dataclass
class X3DHResult:
    shared_secret: bytes
    associated_data: bytes


def _combine(dh_values: list[bytes]) -> bytes:
    # Per spec: prepend 32 0xFF bytes before the DH outputs to prevent
    # cross-protocol attacks (F || DH1 || DH2 || ...).
    ikm = b"\xff" * 32 + b"".join(dh_values)
    return prim.hkdf(ikm, SHARED_SECRET_LEN, salt=b"\x00" * 32, info=INFO)


def initiate(initiator: KeyStore, recipient_bundle: PrekeyBundle) -> tuple[X3DHResult, InitialMessageHeader]:
    """Alice's side: derive the shared secret using Bob's published bundle."""
    if not recipient_bundle.verify_signed_prekey():
        raise PrekeySignatureInvalid("recipient's signed prekey signature does not verify")

    ephemeral_priv = prim.x25519_generate()

    ik_a_priv = initiator.identity_priv_dh
    ek_a_priv = ephemeral_priv
    ik_b_pub = prim.x25519_pub_from_bytes(recipient_bundle.identity_pub_dh)
    spk_b_pub = prim.x25519_pub_from_bytes(recipient_bundle.signed_prekey_pub)

    dh1 = prim.x25519_dh(ik_a_priv, spk_b_pub)
    dh2 = prim.x25519_dh(ek_a_priv, ik_b_pub)
    dh3 = prim.x25519_dh(ek_a_priv, spk_b_pub)
    dh_values = [dh1, dh2, dh3]

    if recipient_bundle.one_time_prekey_pub is not None:
        opk_b_pub = prim.x25519_pub_from_bytes(recipient_bundle.one_time_prekey_pub)
        dh4 = prim.x25519_dh(ek_a_priv, opk_b_pub)
        dh_values.append(dh4)

    shared_secret = _combine(dh_values)
    associated_data = initiator.identity_pub_dh_bytes() + recipient_bundle.identity_pub_dh

    header = InitialMessageHeader(
        initiator_identity_pub_dh=initiator.identity_pub_dh_bytes(),
        initiator_ephemeral_pub=prim.x25519_pub_bytes(ephemeral_priv.public_key()),
        signed_prekey_id=recipient_bundle.signed_prekey_id,
        one_time_prekey_id=recipient_bundle.one_time_prekey_id,
    )
    return X3DHResult(shared_secret=shared_secret, associated_data=associated_data), header


def respond(responder: KeyStore, header: InitialMessageHeader) -> X3DHResult:
    """Bob's side: derive the same shared secret from Alice's init message."""
    if header.signed_prekey_id != responder.signed_prekey.key_id:
        raise ValueError("unknown signed prekey id -- cannot respond to this X3DH init")

    ik_a_pub = prim.x25519_pub_from_bytes(header.initiator_identity_pub_dh)
    ek_a_pub = prim.x25519_pub_from_bytes(header.initiator_ephemeral_pub)
    spk_b_priv = responder.signed_prekey.private_key
    ik_b_priv = responder.identity_priv_dh

    dh1 = prim.x25519_dh(spk_b_priv, ik_a_pub)
    dh2 = prim.x25519_dh(ik_b_priv, ek_a_pub)
    dh3 = prim.x25519_dh(spk_b_priv, ek_a_pub)
    dh_values = [dh1, dh2, dh3]

    if header.one_time_prekey_id is not None:
        otk = responder.one_time_prekeys.get(header.one_time_prekey_id)
        if otk is None:
            raise ValueError("one-time prekey referenced by init message is unknown/already consumed locally")
        dh4 = prim.x25519_dh(otk.private_key, ek_a_pub)
        dh_values.append(dh4)
        # One-time prekeys are single-use: remove it now that it's been used.
        del responder.one_time_prekeys[header.one_time_prekey_id]

    shared_secret = _combine(dh_values)
    associated_data = header.initiator_identity_pub_dh + responder.identity_pub_dh_bytes()
    return X3DHResult(shared_secret=shared_secret, associated_data=associated_data)
