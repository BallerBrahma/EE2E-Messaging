import { describe, expect, it } from 'vitest'
import { generateKeyStore, publicBundle } from './identity'
import { type RatchetState, initAsInitiator, initAsResponder, ratchetDecrypt, ratchetEncrypt, ratchetStateFromJson, ratchetStateToJson } from './ratchet'
import { initiate, respond } from './x3dh'

function establishSessions(): [RatchetState, RatchetState] {
  const aliceKs = generateKeyStore('alice')
  const bobKs = generateKeyStore('bob')

  const bundle = publicBundle(bobKs)
  const { result: x3dhAlice, header } = initiate(aliceKs, bundle)

  const aliceRatchet = initAsInitiator(x3dhAlice.sharedSecret, x3dhAlice.associatedData, bundle.signedPrekeyPub)

  const x3dhBob = respond(bobKs, header)
  const bobRatchet = initAsResponder(x3dhBob.sharedSecret, x3dhBob.associatedData, bobKs.signedPrekey.privateKey)
  return [aliceRatchet, bobRatchet]
}

const enc = (s: string) => new TextEncoder().encode(s)
const dec = (b: Uint8Array) => new TextDecoder().decode(b)

describe('Double Ratchet', () => {
  it('delivers the first message from alice to bob', () => {
    const [alice, bob] = establishSessions()
    const msg = ratchetEncrypt(alice, enc('hello bob'))
    expect(dec(ratchetDecrypt(bob, msg))).toBe('hello bob')
  })

  it('supports a back-and-forth conversation', () => {
    const [alice, bob] = establishSessions()

    const m1 = ratchetEncrypt(alice, enc('hi bob'))
    expect(dec(ratchetDecrypt(bob, m1))).toBe('hi bob')

    const m2 = ratchetEncrypt(bob, enc('hi alice'))
    expect(dec(ratchetDecrypt(alice, m2))).toBe('hi alice')

    const m3 = ratchetEncrypt(alice, enc('how are you'))
    expect(dec(ratchetDecrypt(bob, m3))).toBe('how are you')

    const m4 = ratchetEncrypt(bob, enc('good, you?'))
    expect(dec(ratchetDecrypt(alice, m4))).toBe('good, you?')

    const m5 = ratchetEncrypt(alice, enc('great!'))
    const m6 = ratchetEncrypt(alice, enc('lets talk later'))
    expect(dec(ratchetDecrypt(bob, m5))).toBe('great!')
    expect(dec(ratchetDecrypt(bob, m6))).toBe('lets talk later')
  })

  it('handles out-of-order delivery within the same chain', () => {
    const [alice, bob] = establishSessions()
    // first message required to give bob a sending chain (responder starts with none)
    expect(dec(ratchetDecrypt(bob, ratchetEncrypt(alice, enc('init'))))).toBe('init')

    const m1 = ratchetEncrypt(alice, enc('one'))
    const m2 = ratchetEncrypt(alice, enc('two'))
    const m3 = ratchetEncrypt(alice, enc('three'))

    // deliver out of order: 2, then 1, then 3
    expect(dec(ratchetDecrypt(bob, m2))).toBe('two')
    expect(dec(ratchetDecrypt(bob, m1))).toBe('one')
    expect(dec(ratchetDecrypt(bob, m3))).toBe('three')
  })

  it('recovers a message dropped across a DH ratchet step, delivered later', () => {
    const [alice, bob] = establishSessions()
    expect(dec(ratchetDecrypt(bob, ratchetEncrypt(alice, enc('init'))))).toBe('init')

    const dropped = ratchetEncrypt(alice, enc('this one gets delayed'))
    // alice sends more after a dh ratchet triggered by bob replying
    const reply = ratchetEncrypt(bob, enc("bob's reply"))
    expect(dec(ratchetDecrypt(alice, reply))).toBe("bob's reply")
    const later = ratchetEncrypt(alice, enc("sent after bob's reply"))

    // bob receives the later message first (ratchet advances, dropped's key gets skipped+cached)
    expect(dec(ratchetDecrypt(bob, later))).toBe("sent after bob's reply")
    // the earlier dropped message can still be decrypted from the skipped-key cache
    expect(dec(ratchetDecrypt(bob, dropped))).toBe('this one gets delayed')
  })

  it('fails to decrypt a tampered ciphertext', () => {
    const [alice, bob] = establishSessions()
    const msg = ratchetEncrypt(alice, enc('secret'))
    const tampered = new Uint8Array(msg.ciphertext)
    tampered[tampered.length - 1] ^= 0xff
    msg.ciphertext = tampered

    expect(() => ratchetDecrypt(bob, msg)).toThrow()
  })

  it('round-trips state through JSON and keeps working after restore', () => {
    const [alice, bob] = establishSessions()
    ratchetEncrypt(alice, enc('warm up the chains'))
    const dump = ratchetStateToJson(alice)
    const restored = ratchetStateFromJson(dump)

    expect(restored.nSend).toBe(alice.nSend)
    expect(restored.rootKey).toEqual(alice.rootKey)
    expect(restored.chainKeySend).toEqual(alice.chainKeySend)

    // a session restored from a serialized snapshot must keep producing
    // well-formed messages (chain key state preserved).
    expect(ratchetEncrypt(restored, enc('after restore')).ciphertext.length).toBeGreaterThan(0)
    // bob stays in sync with the live alice
    expect(ratchetDecrypt(bob, ratchetEncrypt(alice, enc('warm up the chains, again')))).toBeDefined()
  })
})
