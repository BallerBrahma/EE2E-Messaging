// X3DH (Extended Triple Diffie-Hellman) initial key agreement -- TypeScript
// port of crypto/x3dh.py. Implements
// https://signal.org/docs/specifications/x3dh/ using X25519 for the DH
// operations. This establishes a shared secret between two parties who
// have never communicated before, using one side's published prekey
// bundle -- the other side does not need to be online.

import { concatBytes, fromBase64, toBase64 } from './encoding'
import { type KeyStore, type PrekeyBundle, verifySignedPrekey } from './identity'
import * as prim from './primitives'

const INFO = new TextEncoder().encode('E2EE-X3DH-v1')
const SHARED_SECRET_LEN = 32

export class PrekeySignatureInvalid extends Error {}

/** Metadata Alice sends to Bob so he can derive the same shared secret. */
export interface InitialMessageHeader {
  initiatorIdentityPubDh: Uint8Array
  initiatorEphemeralPub: Uint8Array
  signedPrekeyId: string
  oneTimePrekeyId: string | null
}

export function initialMessageHeaderToJson(header: InitialMessageHeader): Record<string, unknown> {
  return {
    initiator_identity_pub_dh: toBase64(header.initiatorIdentityPubDh),
    initiator_ephemeral_pub: toBase64(header.initiatorEphemeralPub),
    signed_prekey_id: header.signedPrekeyId,
    one_time_prekey_id: header.oneTimePrekeyId,
  }
}

export function initialMessageHeaderFromJson(data: Record<string, unknown>): InitialMessageHeader {
  return {
    initiatorIdentityPubDh: fromBase64(data.initiator_identity_pub_dh as string),
    initiatorEphemeralPub: fromBase64(data.initiator_ephemeral_pub as string),
    signedPrekeyId: data.signed_prekey_id as string,
    oneTimePrekeyId: (data.one_time_prekey_id as string | null) ?? null,
  }
}

export interface X3dhResult {
  sharedSecret: Uint8Array
  associatedData: Uint8Array
}

function combine(dhValues: Uint8Array[]): Uint8Array {
  // Per spec: prepend 32 0xFF bytes before the DH outputs to prevent
  // cross-protocol attacks (F || DH1 || DH2 || ...).
  const ikm = concatBytes(new Uint8Array(32).fill(0xff), ...dhValues)
  return prim.hkdf(ikm, SHARED_SECRET_LEN, new Uint8Array(32), INFO)
}

/** Alice's side: derive the shared secret using Bob's published bundle. */
export function initiate(
  initiator: KeyStore,
  recipientBundle: PrekeyBundle,
): { result: X3dhResult; header: InitialMessageHeader } {
  if (!verifySignedPrekey(recipientBundle)) {
    throw new PrekeySignatureInvalid("recipient's signed prekey signature does not verify")
  }

  const ephemeralPriv = prim.x25519Generate()

  const ikAPriv = initiator.identityPrivDh
  const ekAPriv = ephemeralPriv
  const ikBPub = recipientBundle.identityPubDh
  const spkBPub = recipientBundle.signedPrekeyPub

  const dh1 = prim.x25519Dh(ikAPriv, spkBPub)
  const dh2 = prim.x25519Dh(ekAPriv, ikBPub)
  const dh3 = prim.x25519Dh(ekAPriv, spkBPub)
  const dhValues = [dh1, dh2, dh3]

  if (recipientBundle.oneTimePrekeyPub !== null) {
    const dh4 = prim.x25519Dh(ekAPriv, recipientBundle.oneTimePrekeyPub)
    dhValues.push(dh4)
  }

  const sharedSecret = combine(dhValues)
  const associatedData = concatBytes(prim.x25519GetPublicKey(initiator.identityPrivDh), recipientBundle.identityPubDh)

  const header: InitialMessageHeader = {
    initiatorIdentityPubDh: prim.x25519GetPublicKey(initiator.identityPrivDh),
    initiatorEphemeralPub: prim.x25519GetPublicKey(ephemeralPriv),
    signedPrekeyId: recipientBundle.signedPrekeyId,
    oneTimePrekeyId: recipientBundle.oneTimePrekeyId,
  }
  return { result: { sharedSecret, associatedData }, header }
}

/** Bob's side: derive the same shared secret from Alice's init message. */
export function respond(responder: KeyStore, header: InitialMessageHeader): X3dhResult {
  if (header.signedPrekeyId !== responder.signedPrekey.keyId) {
    throw new Error('unknown signed prekey id -- cannot respond to this X3DH init')
  }

  const ikAPub = header.initiatorIdentityPubDh
  const ekAPub = header.initiatorEphemeralPub
  const spkBPriv = responder.signedPrekey.privateKey
  const ikBPriv = responder.identityPrivDh

  const dh1 = prim.x25519Dh(spkBPriv, ikAPub)
  const dh2 = prim.x25519Dh(ikBPriv, ekAPub)
  const dh3 = prim.x25519Dh(spkBPriv, ekAPub)
  const dhValues = [dh1, dh2, dh3]

  if (header.oneTimePrekeyId !== null) {
    const otk = responder.oneTimePrekeys.get(header.oneTimePrekeyId)
    if (otk === undefined) {
      throw new Error('one-time prekey referenced by init message is unknown/already consumed locally')
    }
    const dh4 = prim.x25519Dh(otk.privateKey, ekAPub)
    dhValues.push(dh4)
    // One-time prekeys are single-use: remove it now that it's been used.
    responder.oneTimePrekeys.delete(header.oneTimePrekeyId)
  }

  const sharedSecret = combine(dhValues)
  const associatedData = concatBytes(header.initiatorIdentityPubDh, prim.x25519GetPublicKey(responder.identityPrivDh))
  return { sharedSecret, associatedData }
}
