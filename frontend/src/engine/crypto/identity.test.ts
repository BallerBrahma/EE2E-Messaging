import { describe, expect, it } from 'vitest'
import {
  generateKeyStore,
  identityPubDhBytes,
  keyStoreFromJson,
  keyStoreToJson,
  prekeyBundleFromJson,
  prekeyBundleToJson,
  publicBundle,
  topUpOneTimePrekeys,
  verifySignedPrekey,
} from './identity'

describe('KeyStore generation', () => {
  it('generates a keystore with a default pool of one-time prekeys', () => {
    const ks = generateKeyStore('alice')
    expect(ks.username).toBe('alice')
    expect(ks.oneTimePrekeys.size).toBe(20)
  })

  it('produces a public bundle with a verifiable signed-prekey signature', () => {
    const ks = generateKeyStore('alice')
    const bundle = publicBundle(ks)
    expect(bundle.oneTimePrekeyId).not.toBeNull()
    expect(verifySignedPrekey(bundle)).toBe(true)
  })

  it('detects a tampered signed-prekey signature', () => {
    const ks = generateKeyStore('alice')
    const bundle = publicBundle(ks)
    bundle.signedPrekeyPub = ks.signedPrekey.publicKey.slice()
    bundle.signedPrekeyPub[0] ^= 0xff
    expect(verifySignedPrekey(bundle)).toBe(false)
  })

  it('omits the one-time prekey when includeOneTime is false', () => {
    const ks = generateKeyStore('alice')
    const bundle = publicBundle(ks, false)
    expect(bundle.oneTimePrekeyId).toBeNull()
    expect(bundle.oneTimePrekeyPub).toBeNull()
  })
})

describe('topUpOneTimePrekeys', () => {
  it('tops up only the missing amount', () => {
    const ks = generateKeyStore('alice', 5)
    // consume 3
    const ids = Array.from(ks.oneTimePrekeys.keys()).slice(0, 3)
    for (const id of ids) ks.oneTimePrekeys.delete(id)
    expect(ks.oneTimePrekeys.size).toBe(2)

    const added = topUpOneTimePrekeys(ks, 5)
    expect(added.length).toBe(3)
    expect(ks.oneTimePrekeys.size).toBe(5)
  })

  it('adds nothing when already at target', () => {
    const ks = generateKeyStore('alice', 5)
    expect(topUpOneTimePrekeys(ks, 5)).toEqual([])
    expect(ks.oneTimePrekeys.size).toBe(5)
  })
})

describe('serialization', () => {
  it('round-trips a keystore through JSON', () => {
    const ks = generateKeyStore('alice', 3)
    const restored = keyStoreFromJson(keyStoreToJson(ks))
    expect(restored.username).toBe(ks.username)
    expect(identityPubDhBytes(restored)).toEqual(identityPubDhBytes(ks))
    expect(restored.signedPrekey.keyId).toBe(ks.signedPrekey.keyId)
    expect(restored.oneTimePrekeys.size).toBe(ks.oneTimePrekeys.size)
  })

  it('round-trips a prekey bundle through JSON', () => {
    const ks = generateKeyStore('alice')
    const bundle = publicBundle(ks)
    const restored = prekeyBundleFromJson(prekeyBundleToJson(bundle))
    expect(restored).toEqual(bundle)
    expect(verifySignedPrekey(restored)).toBe(true)
  })
})
