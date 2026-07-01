// Identity keys, signed prekeys and one-time prekeys -- TypeScript port of
// crypto/identity.py. Mirrors the key material described in the Signal
// X3DH spec: https://signal.org/docs/specifications/x3dh/
//
// - Identity key: long-term X25519 (for DH) + Ed25519 (for signing).
// - Signed prekey: medium-term X25519 key, signed by the Ed25519 identity key.
// - One-time prekeys: a batch of single-use X25519 keys, consumed by the
//   server on first use by a peer.
//
// Note: `KeyStore.encrypt`/`.decrypt` from the Python version are dead code
// there (nothing calls them -- client/storage.py does its own envelope
// encryption directly), so they're intentionally not ported here either.

import { fromBase64, toBase64 } from './encoding'
import * as prim from './primitives'

export interface SignedPrekey {
  keyId: string
  privateKey: Uint8Array
  publicKey: Uint8Array
  signature: Uint8Array
}

export interface OneTimePrekey {
  keyId: string
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export interface PrekeyBundle {
  identityPubDh: Uint8Array
  identityPubSign: Uint8Array
  signedPrekeyId: string
  signedPrekeyPub: Uint8Array
  signedPrekeySig: Uint8Array
  oneTimePrekeyId: string | null
  oneTimePrekeyPub: Uint8Array | null
}

export interface KeyStore {
  username: string
  identityPrivDh: Uint8Array
  identityPrivSign: Uint8Array
  signedPrekey: SignedPrekey
  oneTimePrekeys: Map<string, OneTimePrekey>
}

export function newKeyId(): string {
  const bytes = prim.randomBytes(8)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export function generateSignedPrekey(identitySignPriv: Uint8Array): SignedPrekey {
  const privateKey = prim.x25519Generate()
  const publicKey = prim.x25519GetPublicKey(privateKey)
  const signature = prim.ed25519Sign(identitySignPriv, publicKey)
  return { keyId: newKeyId(), privateKey, publicKey, signature }
}

export function generateOneTimePrekeys(count: number): OneTimePrekey[] {
  const out: OneTimePrekey[] = []
  for (let i = 0; i < count; i++) {
    const privateKey = prim.x25519Generate()
    const publicKey = prim.x25519GetPublicKey(privateKey)
    out.push({ keyId: newKeyId(), privateKey, publicKey })
  }
  return out
}

export function generateKeyStore(username: string, oneTimePrekeyCount = 20): KeyStore {
  const identityPrivDh = prim.x25519Generate()
  const identityPrivSign = prim.ed25519Generate()
  const signedPrekey = generateSignedPrekey(identityPrivSign)
  const otks = generateOneTimePrekeys(oneTimePrekeyCount)
  return {
    username,
    identityPrivDh,
    identityPrivSign,
    signedPrekey,
    oneTimePrekeys: new Map(otks.map((k) => [k.keyId, k])),
  }
}

export function identityPubDhBytes(keystore: KeyStore): Uint8Array {
  return prim.x25519GetPublicKey(keystore.identityPrivDh)
}

export function identityPubSignBytes(keystore: KeyStore): Uint8Array {
  return prim.ed25519GetPublicKey(keystore.identityPrivSign)
}

export function publicBundle(keystore: KeyStore, includeOneTime = true): PrekeyBundle {
  let oneTimePrekeyId: string | null = null
  let oneTimePrekeyPub: Uint8Array | null = null
  if (includeOneTime && keystore.oneTimePrekeys.size > 0) {
    const otk = keystore.oneTimePrekeys.values().next().value as OneTimePrekey
    oneTimePrekeyId = otk.keyId
    oneTimePrekeyPub = otk.publicKey
  }
  return {
    identityPubDh: identityPubDhBytes(keystore),
    identityPubSign: identityPubSignBytes(keystore),
    signedPrekeyId: keystore.signedPrekey.keyId,
    signedPrekeyPub: keystore.signedPrekey.publicKey,
    signedPrekeySig: keystore.signedPrekey.signature,
    oneTimePrekeyId,
    oneTimePrekeyPub,
  }
}

/** Generates new one-time prekeys if the local pool is running low, mutating
 * `keystore.oneTimePrekeys` in place. Returns the newly generated keys (empty
 * if the pool was already at/above target). */
export function topUpOneTimePrekeys(keystore: KeyStore, targetCount = 20): OneTimePrekey[] {
  const needed = targetCount - keystore.oneTimePrekeys.size
  if (needed <= 0) return []
  const newKeys = generateOneTimePrekeys(needed)
  for (const k of newKeys) keystore.oneTimePrekeys.set(k.keyId, k)
  return newKeys
}

export function verifySignedPrekey(bundle: PrekeyBundle): boolean {
  return prim.ed25519Verify(bundle.identityPubSign, bundle.signedPrekeySig, bundle.signedPrekeyPub)
}

// -- serialization ------------------------------------------------------------

export function prekeyBundleToJson(bundle: PrekeyBundle): Record<string, unknown> {
  return {
    identity_pub_dh: toBase64(bundle.identityPubDh),
    identity_pub_sign: toBase64(bundle.identityPubSign),
    signed_prekey_id: bundle.signedPrekeyId,
    signed_prekey_pub: toBase64(bundle.signedPrekeyPub),
    signed_prekey_sig: toBase64(bundle.signedPrekeySig),
    one_time_prekey_id: bundle.oneTimePrekeyId,
    one_time_prekey_pub: bundle.oneTimePrekeyPub ? toBase64(bundle.oneTimePrekeyPub) : null,
  }
}

export function prekeyBundleFromJson(data: Record<string, unknown>): PrekeyBundle {
  return {
    identityPubDh: fromBase64(data.identity_pub_dh as string),
    identityPubSign: fromBase64(data.identity_pub_sign as string),
    signedPrekeyId: data.signed_prekey_id as string,
    signedPrekeyPub: fromBase64(data.signed_prekey_pub as string),
    signedPrekeySig: fromBase64(data.signed_prekey_sig as string),
    oneTimePrekeyId: (data.one_time_prekey_id as string | null) ?? null,
    oneTimePrekeyPub: data.one_time_prekey_pub ? fromBase64(data.one_time_prekey_pub as string) : null,
  }
}

export function keyStoreToJson(keystore: KeyStore): Record<string, unknown> {
  return {
    username: keystore.username,
    identity_priv_dh: toBase64(keystore.identityPrivDh),
    identity_priv_sign: toBase64(keystore.identityPrivSign),
    signed_prekey: {
      key_id: keystore.signedPrekey.keyId,
      private_key: toBase64(keystore.signedPrekey.privateKey),
      signature: toBase64(keystore.signedPrekey.signature),
    },
    one_time_prekeys: Object.fromEntries(
      Array.from(keystore.oneTimePrekeys.entries()).map(([id, otk]) => [id, toBase64(otk.privateKey)]),
    ),
  }
}

export function keyStoreFromJson(data: Record<string, unknown>): KeyStore {
  const identityPrivDh = fromBase64(data.identity_priv_dh as string)
  const identityPrivSign = fromBase64(data.identity_priv_sign as string)
  const sp = data.signed_prekey as Record<string, unknown>
  const spPriv = fromBase64(sp.private_key as string)
  const signedPrekey: SignedPrekey = {
    keyId: sp.key_id as string,
    privateKey: spPriv,
    publicKey: prim.x25519GetPublicKey(spPriv),
    signature: fromBase64(sp.signature as string),
  }
  const otks = new Map<string, OneTimePrekey>()
  const rawOtks = data.one_time_prekeys as Record<string, string>
  for (const [keyId, privB64] of Object.entries(rawOtks)) {
    const priv = fromBase64(privB64)
    otks.set(keyId, { keyId, privateKey: priv, publicKey: prim.x25519GetPublicKey(priv) })
  }
  return {
    username: data.username as string,
    identityPrivDh,
    identityPrivSign,
    signedPrekey,
    oneTimePrekeys: otks,
  }
}
