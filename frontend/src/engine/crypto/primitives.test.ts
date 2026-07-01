import { describe, expect, it } from 'vitest'
import {
  DecryptionError,
  aeadDecrypt,
  aeadEncrypt,
  deriveKeyFromPassword,
  ed25519Generate,
  ed25519GetPublicKey,
  ed25519Sign,
  ed25519Verify,
  hkdf,
  newSalt,
  randomBytes,
  x25519Dh,
  x25519Generate,
  x25519GetPublicKey,
} from './primitives'

describe('AEAD (AES-256-GCM)', () => {
  it('round-trips plaintext with matching associated data', () => {
    const key = randomBytes(32)
    const aad = new TextEncoder().encode('header bytes')
    const plaintext = new TextEncoder().encode('hello, world')
    const blob = aeadEncrypt(key, plaintext, aad)
    const decrypted = aeadDecrypt(key, blob, aad)
    expect(new TextDecoder().decode(decrypted)).toBe('hello, world')
  })

  it('rejects a tampered ciphertext', () => {
    const key = randomBytes(32)
    const blob = aeadEncrypt(key, new TextEncoder().encode('secret'))
    const tampered = new Uint8Array(blob)
    tampered[tampered.length - 1] ^= 0xff
    expect(() => aeadDecrypt(key, tampered)).toThrow(DecryptionError)
  })

  it('rejects mismatched associated data', () => {
    const key = randomBytes(32)
    const blob = aeadEncrypt(key, new TextEncoder().encode('secret'), new TextEncoder().encode('a'))
    expect(() => aeadDecrypt(key, blob, new TextEncoder().encode('b'))).toThrow(DecryptionError)
  })

  it('rejects decryption under the wrong key', () => {
    const blob = aeadEncrypt(randomBytes(32), new TextEncoder().encode('secret'))
    expect(() => aeadDecrypt(randomBytes(32), blob)).toThrow(DecryptionError)
  })
})

describe('HKDF', () => {
  it('is deterministic for the same inputs', () => {
    const ikm = randomBytes(32)
    const salt = randomBytes(32)
    const info = new TextEncoder().encode('info')
    expect(hkdf(ikm, 32, salt, info)).toEqual(hkdf(ikm, 32, salt, info))
  })

  it('differs when info differs', () => {
    const ikm = randomBytes(32)
    const salt = randomBytes(32)
    const a = hkdf(ikm, 32, salt, new TextEncoder().encode('a'))
    const b = hkdf(ikm, 32, salt, new TextEncoder().encode('b'))
    expect(a).not.toEqual(b)
  })
})

describe('Scrypt password KDF', () => {
  it('derives a stable key for the same password+salt', async () => {
    const salt = newSalt()
    const a = await deriveKeyFromPassword('correct horse battery staple', salt)
    const b = await deriveKeyFromPassword('correct horse battery staple', salt)
    expect(a).toEqual(b)
    expect(a.length).toBe(32)
  })

  it('derives a different key for a different password', async () => {
    const salt = newSalt()
    const a = await deriveKeyFromPassword('password one', salt)
    const b = await deriveKeyFromPassword('password two', salt)
    expect(a).not.toEqual(b)
  })
})

describe('X25519', () => {
  it('both sides derive the same shared secret', () => {
    const alicePriv = x25519Generate()
    const alicePub = x25519GetPublicKey(alicePriv)
    const bobPriv = x25519Generate()
    const bobPub = x25519GetPublicKey(bobPriv)

    const sharedAlice = x25519Dh(alicePriv, bobPub)
    const sharedBob = x25519Dh(bobPriv, alicePub)
    expect(sharedAlice).toEqual(sharedBob)
  })
})

describe('Ed25519', () => {
  it('verifies a valid signature and rejects a tampered message', () => {
    const priv = ed25519Generate()
    const pub = ed25519GetPublicKey(priv)
    const message = new TextEncoder().encode('sign me')
    const signature = ed25519Sign(priv, message)

    expect(ed25519Verify(pub, signature, message)).toBe(true)
    expect(ed25519Verify(pub, signature, new TextEncoder().encode('sign me!'))).toBe(false)
  })
})
