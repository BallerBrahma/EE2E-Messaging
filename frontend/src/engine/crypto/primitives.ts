// Low-level cryptographic building blocks -- TypeScript port of
// crypto/primitives.py. Everything here is a thin wrapper around
// @noble/curves, @noble/hashes and @noble/ciphers (pure TS, audited, no
// WASM/native deps -- see the "Password recovery" section of the plan for
// why these were chosen over native WebCrypto for X25519/Ed25519/Scrypt).
// No custom cryptography is implemented here or anywhere else -- only
// well-known algorithms from audited libraries, same rule as the Python
// side.
//
// Note on keys: unlike the Python `cryptography` package, noble represents
// X25519/Ed25519 keys as plain `Uint8Array` (no key-object wrapper), so
// there's no equivalent of Python's `x25519_priv_bytes`/`_from_bytes`
// serialization helpers needed here -- a key already *is* its bytes.

import { gcm } from '@noble/ciphers/aes.js'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { scryptAsync } from '@noble/hashes/scrypt.js'
import { sha256 } from '@noble/hashes/sha2.js'

export const AEAD_KEY_LEN = 32 // AES-256-GCM
export const AEAD_NONCE_LEN = 12
export const X25519_KEY_LEN = 32
export const ED25519_KEY_LEN = 32
export const SCRYPT_SALT_LEN = 16

export class DecryptionError extends Error {}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length)
  crypto.getRandomValues(out)
  return out
}

// -- AEAD (AES-256-GCM) -----------------------------------------------------

export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array = new Uint8Array(),
): Uint8Array {
  const nonce = randomBytes(AEAD_NONCE_LEN)
  const ciphertext = gcm(key, nonce, associatedData).encrypt(plaintext)
  const out = new Uint8Array(nonce.length + ciphertext.length)
  out.set(nonce, 0)
  out.set(ciphertext, nonce.length)
  return out
}

export function aeadDecrypt(
  key: Uint8Array,
  blob: Uint8Array,
  associatedData: Uint8Array = new Uint8Array(),
): Uint8Array {
  if (blob.length < AEAD_NONCE_LEN) throw new DecryptionError('ciphertext too short')
  const nonce = blob.subarray(0, AEAD_NONCE_LEN)
  const ciphertext = blob.subarray(AEAD_NONCE_LEN)
  try {
    return gcm(key, nonce, associatedData).decrypt(ciphertext)
  } catch (exc) {
    throw new DecryptionError('authentication failed')
  }
}

// -- HKDF / HMAC --------------------------------------------------------------

export function hkdf(inputKeyMaterial: Uint8Array, length: number, salt: Uint8Array | undefined, info: Uint8Array): Uint8Array {
  return nobleHkdf(sha256, inputKeyMaterial, salt, info, length)
}

export function hkdfMulti(
  inputKeyMaterial: Uint8Array,
  length: number,
  salt: Uint8Array | undefined,
  info: Uint8Array,
  n: number,
): Uint8Array[] {
  const out = hkdf(inputKeyMaterial, length * n, salt, info)
  const chunks: Uint8Array[] = []
  for (let i = 0; i < n; i++) chunks.push(out.subarray(i * length, (i + 1) * length))
  return chunks
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data)
}

// -- Password-based key derivation (Scrypt) -- used for the local keystore --

export async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
  return scryptAsync(new TextEncoder().encode(password), salt, { N: 2 ** 15, r: 8, p: 1, dkLen: AEAD_KEY_LEN })
}

export function newSalt(): Uint8Array {
  return randomBytes(SCRYPT_SALT_LEN)
}

// -- X25519 (DH) helpers ------------------------------------------------------

export function x25519Generate(): Uint8Array {
  return x25519.utils.randomSecretKey()
}

export function x25519GetPublicKey(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey)
}

export function x25519Dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey)
}

// -- Ed25519 (signing) helpers --------------------------------------------------

export function ed25519Generate(): Uint8Array {
  return ed25519.utils.randomSecretKey()
}

export function ed25519GetPublicKey(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey)
}

export function ed25519Sign(privateKey: Uint8Array, data: Uint8Array): Uint8Array {
  return ed25519.sign(data, privateKey)
}

export function ed25519Verify(publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, data, publicKey)
  } catch {
    return false
  }
}
