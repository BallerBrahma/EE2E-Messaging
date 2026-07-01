import { describe, expect, it } from 'vitest'
import { generateKeyStore, publicBundle } from './identity'
import { PrekeySignatureInvalid, initialMessageHeaderFromJson, initialMessageHeaderToJson, initiate, respond } from './x3dh'

describe('X3DH', () => {
  it('derives a matching shared secret with a one-time prekey', () => {
    const alice = generateKeyStore('alice')
    const bob = generateKeyStore('bob')

    const bundle = publicBundle(bob, true)
    expect(bundle.oneTimePrekeyId).not.toBeNull()

    const { result: resultA, header } = initiate(alice, bundle)
    const resultB = respond(bob, header)

    expect(resultA.sharedSecret).toEqual(resultB.sharedSecret)
    expect(resultA.associatedData).toEqual(resultB.associatedData)
    // the one-time prekey must be consumed on the responder side
    expect(bob.oneTimePrekeys.has(header.oneTimePrekeyId as string)).toBe(false)
  })

  it('derives a matching shared secret without a one-time prekey', () => {
    const alice = generateKeyStore('alice')
    const bob = generateKeyStore('bob')
    bob.oneTimePrekeys.clear()

    const bundle = publicBundle(bob, true)
    expect(bundle.oneTimePrekeyId).toBeNull()

    const { result: resultA, header } = initiate(alice, bundle)
    const resultB = respond(bob, header)
    expect(resultA.sharedSecret).toEqual(resultB.sharedSecret)
  })

  it('rejects a tampered signed-prekey signature', () => {
    const alice = generateKeyStore('alice')
    const bob = generateKeyStore('bob')
    const bundle = publicBundle(bob)
    bundle.signedPrekeySig = new Uint8Array(bundle.signedPrekeySig.length)

    expect(() => initiate(alice, bundle)).toThrow(PrekeySignatureInvalid)
  })

  it('round-trips the header through JSON', () => {
    const alice = generateKeyStore('alice')
    const bob = generateKeyStore('bob')
    const bundle = publicBundle(bob)
    const { header } = initiate(alice, bundle)

    const restored = initialMessageHeaderFromJson(initialMessageHeaderToJson(header))
    expect(restored).toEqual(header)
  })
})
