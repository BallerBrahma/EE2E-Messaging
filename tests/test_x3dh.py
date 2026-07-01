from crypto import x3dh
from crypto.identity import KeyStore


def test_x3dh_shared_secret_matches_with_one_time_prekey():
    alice = KeyStore.generate("alice")
    bob = KeyStore.generate("bob")

    bundle = bob.public_bundle(include_one_time=True)
    assert bundle.one_time_prekey_id is not None

    result_a, header = x3dh.initiate(alice, bundle)
    result_b = x3dh.respond(bob, header)

    assert result_a.shared_secret == result_b.shared_secret
    assert result_a.associated_data == result_b.associated_data
    # the one-time prekey must be consumed on the responder side
    assert header.one_time_prekey_id not in bob.one_time_prekeys


def test_x3dh_shared_secret_matches_without_one_time_prekey():
    alice = KeyStore.generate("alice")
    bob = KeyStore.generate("bob")
    bob.one_time_prekeys.clear()

    bundle = bob.public_bundle(include_one_time=True)
    assert bundle.one_time_prekey_id is None

    result_a, header = x3dh.initiate(alice, bundle)
    result_b = x3dh.respond(bob, header)

    assert result_a.shared_secret == result_b.shared_secret


def test_x3dh_rejects_tampered_signed_prekey_signature():
    alice = KeyStore.generate("alice")
    bob = KeyStore.generate("bob")
    bundle = bob.public_bundle()
    bundle.signed_prekey_sig = b"\x00" * len(bundle.signed_prekey_sig)

    try:
        x3dh.initiate(alice, bundle)
        assert False, "expected PrekeySignatureInvalid"
    except x3dh.PrekeySignatureInvalid:
        pass


def test_header_roundtrips_through_json():
    alice = KeyStore.generate("alice")
    bob = KeyStore.generate("bob")
    bundle = bob.public_bundle()
    _, header = x3dh.initiate(alice, bundle)

    restored = x3dh.InitialMessageHeader.from_json(header.to_json())
    assert restored == header
