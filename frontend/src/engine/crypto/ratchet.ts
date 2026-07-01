// Double Ratchet algorithm -- TypeScript port of crypto/ratchet.py.
// Implements https://signal.org/docs/specifications/doubleratchet/ on top
// of X25519 (DH ratchet) + HKDF/HMAC-SHA256 (KDF chains) + AES-256-GCM
// (message encryption). Provides forward secrecy (old message keys can't
// decrypt new messages and vice versa) and post-compromise security (a
// compromised chain key heals itself after the next DH ratchet step), plus
// out-of-order message handling via a skipped-message-key cache.
//
// Note: Python's skipped-key cache is keyed by a `(dh_pub: bytes, n: int)`
// tuple, relying on `bytes` being a hashable value type. Uint8Array has no
// such value-equality in JS, so this port keys the cache by a
// `base64(dh_pub):n` string instead -- same lookup semantics.

import { bytesEqual, concatBytes, fromBase64, toBase64 } from './encoding'
import * as prim from './primitives'

const MAX_SKIP = 1000
const ROOT_INFO = new TextEncoder().encode('E2EE-ratchet-root-v1')
const MSG_KEY_CONST = new Uint8Array([0x01])
const CHAIN_KEY_CONST = new Uint8Array([0x02])

export class RatchetError extends Error {}

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n, false)
  return out
}

export function kdfRk(rootKey: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const out = prim.hkdf(dhOut, 64, rootKey, ROOT_INFO)
  return [out.subarray(0, 32), out.subarray(32)]
}

export function kdfCk(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const nextChainKey = prim.hmacSha256(chainKey, CHAIN_KEY_CONST)
  const messageKey = prim.hmacSha256(chainKey, MSG_KEY_CONST)
  return [nextChainKey, messageKey]
}

export interface MessageHeader {
  dhPub: Uint8Array
  pn: number
  n: number
}

export function messageHeaderToBytes(header: MessageHeader): Uint8Array {
  // Used as AEAD associated data -- bind header fields to the ciphertext.
  return concatBytes(header.dhPub, u32be(header.pn), u32be(header.n))
}

export function messageHeaderToJson(header: MessageHeader): Record<string, unknown> {
  return { dh_pub: toBase64(header.dhPub), pn: header.pn, n: header.n }
}

export function messageHeaderFromJson(data: Record<string, unknown>): MessageHeader {
  return { dhPub: fromBase64(data.dh_pub as string), pn: data.pn as number, n: data.n as number }
}

export interface RatchetMessage {
  header: MessageHeader
  ciphertext: Uint8Array
}

export function ratchetMessageToJson(message: RatchetMessage): Record<string, unknown> {
  return { header: messageHeaderToJson(message.header), ciphertext: toBase64(message.ciphertext) }
}

export function ratchetMessageFromJson(data: Record<string, unknown>): RatchetMessage {
  return {
    header: messageHeaderFromJson(data.header as Record<string, unknown>),
    ciphertext: fromBase64(data.ciphertext as string),
  }
}

export interface RatchetState {
  dhsPriv: Uint8Array
  dhrPub: Uint8Array | null
  rootKey: Uint8Array
  chainKeySend: Uint8Array | null
  chainKeyRecv: Uint8Array | null
  nSend: number
  nRecv: number
  prevChainLen: number
  skipped: Map<string, Uint8Array>
  associatedData: Uint8Array
}

function skipKey(dhPub: Uint8Array, n: number): string {
  return `${toBase64(dhPub)}:${n}`
}

/** Alice's side, called right after x3dh.initiate(). */
export function initAsInitiator(sharedSecret: Uint8Array, associatedData: Uint8Array, remoteRatchetPub: Uint8Array): RatchetState {
  const dhsPriv = prim.x25519Generate()
  const dhOut = prim.x25519Dh(dhsPriv, remoteRatchetPub)
  const [rootKey, chainKeySend] = kdfRk(sharedSecret, dhOut)
  return {
    dhsPriv,
    dhrPub: remoteRatchetPub,
    rootKey,
    chainKeySend,
    chainKeyRecv: null,
    nSend: 0,
    nRecv: 0,
    prevChainLen: 0,
    skipped: new Map(),
    associatedData,
  }
}

/** Bob's side. ownRatchetPriv is his signed-prekey private key, which
 * doubled as the initial ratchet keypair Alice used in X3DH. */
export function initAsResponder(sharedSecret: Uint8Array, associatedData: Uint8Array, ownRatchetPriv: Uint8Array): RatchetState {
  return {
    dhsPriv: ownRatchetPriv,
    dhrPub: null,
    rootKey: sharedSecret,
    chainKeySend: null,
    chainKeyRecv: null,
    nSend: 0,
    nRecv: 0,
    prevChainLen: 0,
    skipped: new Map(),
    associatedData,
  }
}

export function ratchetEncrypt(state: RatchetState, plaintext: Uint8Array): RatchetMessage {
  if (state.chainKeySend === null) {
    throw new RatchetError('no sending chain established yet (responder must receive first)')
  }
  const [nextChainKey, messageKey] = kdfCk(state.chainKeySend)
  state.chainKeySend = nextChainKey
  const header: MessageHeader = { dhPub: prim.x25519GetPublicKey(state.dhsPriv), pn: state.prevChainLen, n: state.nSend }
  state.nSend += 1
  const ciphertext = prim.aeadEncrypt(messageKey, plaintext, concatBytes(state.associatedData, messageHeaderToBytes(header)))
  return { header, ciphertext }
}

export function ratchetDecrypt(state: RatchetState, message: RatchetMessage): Uint8Array {
  const key = skipKey(message.header.dhPub, message.header.n)
  const cachedKey = state.skipped.get(key)
  if (cachedKey !== undefined) {
    state.skipped.delete(key)
    return prim.aeadDecrypt(cachedKey, message.ciphertext, concatBytes(state.associatedData, messageHeaderToBytes(message.header)))
  }

  if (state.dhrPub === null || !bytesEqual(message.header.dhPub, state.dhrPub)) {
    skipMessageKeys(state, message.header.pn)
    dhRatchet(state, message.header.dhPub)
  }

  skipMessageKeys(state, message.header.n)
  const [nextChainKey, messageKey] = kdfCk(state.chainKeyRecv as Uint8Array)
  state.chainKeyRecv = nextChainKey
  state.nRecv += 1
  return prim.aeadDecrypt(messageKey, message.ciphertext, concatBytes(state.associatedData, messageHeaderToBytes(message.header)))
}

function skipMessageKeys(state: RatchetState, until: number): void {
  if (state.chainKeyRecv === null) return
  if (until - state.nRecv > MAX_SKIP) {
    throw new RatchetError('too many skipped messages -- refusing (possible DoS)')
  }
  while (state.nRecv < until) {
    const [nextChainKey, messageKey] = kdfCk(state.chainKeyRecv)
    state.chainKeyRecv = nextChainKey
    state.skipped.set(skipKey(state.dhrPub as Uint8Array, state.nRecv), messageKey)
    state.nRecv += 1
  }
}

function dhRatchet(state: RatchetState, newDhrPub: Uint8Array): void {
  state.prevChainLen = state.nSend
  state.nSend = 0
  state.nRecv = 0
  state.dhrPub = newDhrPub

  let dhOut = prim.x25519Dh(state.dhsPriv, state.dhrPub)
  ;[state.rootKey, state.chainKeyRecv] = kdfRk(state.rootKey, dhOut)

  state.dhsPriv = prim.x25519Generate()
  dhOut = prim.x25519Dh(state.dhsPriv, state.dhrPub)
  ;[state.rootKey, state.chainKeySend] = kdfRk(state.rootKey, dhOut)
}

// -- serialization ---------------------------------------------------------

export function ratchetStateToJson(state: RatchetState): Record<string, unknown> {
  return {
    dhs_priv: toBase64(state.dhsPriv),
    dhr_pub: state.dhrPub ? toBase64(state.dhrPub) : null,
    root_key: toBase64(state.rootKey),
    chain_key_send: state.chainKeySend ? toBase64(state.chainKeySend) : null,
    chain_key_recv: state.chainKeyRecv ? toBase64(state.chainKeyRecv) : null,
    n_send: state.nSend,
    n_recv: state.nRecv,
    prev_chain_len: state.prevChainLen,
    skipped: Array.from(state.skipped.entries()).map(([key, mk]) => {
      const [dhB64, nStr] = key.split(':')
      return { dh_pub: dhB64, n: Number(nStr), mk: toBase64(mk) }
    }),
    associated_data: toBase64(state.associatedData),
  }
}

export function ratchetStateFromJson(data: Record<string, unknown>): RatchetState {
  const skipped = new Map<string, Uint8Array>()
  for (const item of data.skipped as { dh_pub: string; n: number; mk: string }[]) {
    skipped.set(`${item.dh_pub}:${item.n}`, fromBase64(item.mk))
  }
  return {
    dhsPriv: fromBase64(data.dhs_priv as string),
    dhrPub: data.dhr_pub ? fromBase64(data.dhr_pub as string) : null,
    rootKey: fromBase64(data.root_key as string),
    chainKeySend: data.chain_key_send ? fromBase64(data.chain_key_send as string) : null,
    chainKeyRecv: data.chain_key_recv ? fromBase64(data.chain_key_recv as string) : null,
    nSend: data.n_send as number,
    nRecv: data.n_recv as number,
    prevChainLen: data.prev_chain_len as number,
    skipped,
    associatedData: fromBase64(data.associated_data as string),
  }
}
