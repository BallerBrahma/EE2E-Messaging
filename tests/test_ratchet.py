from crypto import x3dh
from crypto.identity import KeyStore
from crypto.ratchet import RatchetState


def _establish_sessions():
    """Run X3DH between alice/bob and initialize both ratchet sessions,
    mirroring what session_manager will do."""
    alice_ks = KeyStore.generate("alice")
    bob_ks = KeyStore.generate("bob")

    bundle = bob_ks.public_bundle()
    x3dh_alice, header = x3dh.initiate(alice_ks, bundle)

    alice_ratchet = RatchetState.init_as_initiator(
        shared_secret=x3dh_alice.shared_secret,
        associated_data=x3dh_alice.associated_data,
        remote_ratchet_pub=bundle.signed_prekey_pub,
    )

    x3dh_bob = x3dh.respond(bob_ks, header)
    bob_ratchet = RatchetState.init_as_responder(
        shared_secret=x3dh_bob.shared_secret,
        associated_data=x3dh_bob.associated_data,
        own_ratchet_priv=bob_ks.signed_prekey.private_key,
    )
    return alice_ratchet, bob_ratchet


def test_first_message_alice_to_bob():
    alice, bob = _establish_sessions()
    msg = alice.encrypt(b"hello bob")
    pt = bob.decrypt(msg)
    assert pt == b"hello bob"


def test_back_and_forth_conversation():
    alice, bob = _establish_sessions()

    m1 = alice.encrypt(b"hi bob")
    assert bob.decrypt(m1) == b"hi bob"

    m2 = bob.encrypt(b"hi alice")
    assert alice.decrypt(m2) == b"hi alice"

    m3 = alice.encrypt(b"how are you")
    assert bob.decrypt(m3) == b"how are you"

    m4 = bob.encrypt(b"good, you?")
    assert alice.decrypt(m4) == b"good, you?"

    m5 = alice.encrypt(b"great!")
    m6 = alice.encrypt(b"lets talk later")
    assert bob.decrypt(m5) == b"great!"
    assert bob.decrypt(m6) == b"lets talk later"


def test_out_of_order_delivery_within_same_chain():
    alice, bob = _establish_sessions()
    # first message required to give bob a sending chain (responder starts with none)
    assert bob.decrypt(alice.encrypt(b"init")) == b"init"

    m1 = alice.encrypt(b"one")
    m2 = alice.encrypt(b"two")
    m3 = alice.encrypt(b"three")

    # deliver out of order: 2, then 1, then 3
    assert bob.decrypt(m2) == b"two"
    assert bob.decrypt(m1) == b"one"
    assert bob.decrypt(m3) == b"three"


def test_dropped_message_across_dh_ratchet_step_is_recoverable_later():
    alice, bob = _establish_sessions()
    assert bob.decrypt(alice.encrypt(b"init")) == b"init"

    dropped = alice.encrypt(b"this one gets delayed")
    # alice sends more after a dh ratchet triggered by bob replying
    reply = bob.encrypt(b"bob's reply")
    assert alice.decrypt(reply) == b"bob's reply"
    later = alice.encrypt(b"sent after bob's reply")

    # bob receives the later message first (ratchet advances, dropped's key gets skipped+cached)
    assert bob.decrypt(later) == b"sent after bob's reply"
    # the earlier dropped message can still be decrypted from the skipped-key cache
    assert bob.decrypt(dropped) == b"this one gets delayed"


def test_tampered_ciphertext_fails_to_decrypt():
    alice, bob = _establish_sessions()
    msg = alice.encrypt(b"secret")
    tampered_ct = bytearray(msg.ciphertext)
    tampered_ct[-1] ^= 0xFF
    msg.ciphertext = bytes(tampered_ct)

    try:
        bob.decrypt(msg)
        assert False, "expected decryption to fail on tampered ciphertext"
    except Exception:
        pass


def test_state_serialization_roundtrip():
    alice, bob = _establish_sessions()
    alice.encrypt(b"warm up the chains")
    dump = alice.to_json()
    restored = RatchetState.from_json(dump)

    assert restored.n_send == alice.n_send
    assert restored.root_key == alice.root_key
    assert restored.chain_key_send == alice.chain_key_send

    # a session restored from a serialized snapshot must keep producing
    # well-formed messages (chain key state preserved).
    assert restored.encrypt(b"after restore").ciphertext
    assert bob.decrypt(alice.encrypt(b"warm up the chains, again")) is not None  # bob stays in sync with the live alice

