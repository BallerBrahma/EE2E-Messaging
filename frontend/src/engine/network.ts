// WebSocket client for talking to the relay server -- TypeScript port of
// client/network.py, using the browser's native `WebSocket` (no import
// needed -- it's a global, same as in the real deployed environment).
//
// A single `onmessage` handler processes all incoming frames:
// request/response pairs (register, login, upload_keys, fetch_bundle,
// send_message) are correlated by simply waiting for the next non-pushed
// frame, since this client only ever has one request in flight at a time
// (same constraint as the Python version). Server-pushed `incoming_message`
// frames are routed to `onMessage` instead of the response queue.
//
// NOTE: not safe to call request methods concurrently -- same caveat as
// client/network.py.

import { toBase64 } from './crypto/encoding'
import { type KeyStore, type PrekeyBundle, prekeyBundleFromJson, publicBundle } from './crypto/identity'

export class ServerError extends Error {}

export interface IncomingMessage {
  id: number
  sender: string
  payload: Record<string, unknown>
  createdAt: number
}

type MessageHandler = (msg: IncomingMessage) => void | Promise<void>
type PresenceHandler = (username: string, online: boolean) => void | Promise<void>
type PresenceSnapshotHandler = (onlineUsernames: string[]) => void | Promise<void>

/** Minimal single-consumer async queue -- mirrors the role of Python's
 * asyncio.Queue for correlating one-request-in-flight-at-a-time responses. */
class AsyncQueue<T> {
  private items: T[] = []
  private waiters: ((value: T) => void)[] = []

  push(item: T): void {
    const waiter = this.waiters.shift()
    if (waiter) waiter(item)
    else this.items.push(item)
  }

  pop(): Promise<T> {
    const item = this.items.shift()
    if (item !== undefined) return Promise.resolve(item)
    return new Promise<T>((resolve) => this.waiters.push(resolve))
  }
}

export class NetworkClient {
  readonly uri: string
  username: string | null = null
  onMessage: MessageHandler | null = null
  onPresence: PresenceHandler | null = null
  onPresenceSnapshot: PresenceSnapshotHandler | null = null

  private ws: WebSocket | null = null
  private responseQueue = new AsyncQueue<Record<string, unknown>>()

  constructor(uri: string) {
    this.uri = uri
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.uri)
      ws.onopen = () => {
        this.ws = ws
        resolve()
      }
      ws.onerror = () => reject(new Error(`failed to connect to relay server at ${this.uri}`))
      ws.onmessage = (event) => this.handleFrame(event.data as string)
    })
  }

  async close(): Promise<void> {
    this.ws?.close()
    this.ws = null
  }

  private handleFrame(raw: string): void {
    const msg = JSON.parse(raw) as Record<string, unknown>
    const msgType = msg.type
    if (msgType === 'incoming_message') {
      void this.onMessage?.({
        id: msg.id as number,
        sender: msg.sender as string,
        payload: msg.payload as Record<string, unknown>,
        createdAt: msg.created_at as number,
      })
    } else if (msgType === 'presence') {
      void this.onPresence?.(msg.username as string, msg.online as boolean)
    } else if (msgType === 'presence_snapshot') {
      void this.onPresenceSnapshot?.(msg.online_usernames as string[])
    } else {
      this.responseQueue.push(msg)
    }
  }

  private async request(req: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (this.ws === null) throw new Error('call connect() first')
    this.ws.send(JSON.stringify(req))
    const response = await this.responseQueue.pop()
    if (response.type === 'error') {
      throw new ServerError((response.message as string) ?? 'unknown server error')
    }
    return response
  }

  // -- account ---------------------------------------------------------------

  async register(username: string, password: string): Promise<void> {
    await this.request({ type: 'register', username, password })
  }

  async login(username: string, password: string): Promise<void> {
    const response = await this.request({ type: 'login', username, password })
    this.username = response.username as string
  }

  // -- keys ---------------------------------------------------------------------

  async uploadKeys(keystore: KeyStore): Promise<void> {
    const bundle = publicBundle(keystore, false)
    const request = {
      type: 'upload_keys',
      identity_pub_dh: toBase64(bundle.identityPubDh),
      identity_pub_sign: toBase64(bundle.identityPubSign),
      signed_prekey_id: bundle.signedPrekeyId,
      signed_prekey_pub: toBase64(bundle.signedPrekeyPub),
      signed_prekey_sig: toBase64(bundle.signedPrekeySig),
      one_time_prekeys: Array.from(keystore.oneTimePrekeys.values()).map((otk) => ({
        key_id: otk.keyId,
        public_key: toBase64(otk.publicKey),
      })),
    }
    await this.request(request)
  }

  async fetchBundle(username: string): Promise<PrekeyBundle | null> {
    const response = await this.request({ type: 'fetch_bundle', username })
    if (response.bundle === null) return null
    return prekeyBundleFromJson(response.bundle as Record<string, unknown>)
  }

  // -- messaging ------------------------------------------------------------------

  async sendMessage(recipient: string, payload: Record<string, unknown>): Promise<void> {
    await this.request({ type: 'send_message', recipient, payload })
  }
}

// referenced only for parity/documentation with client/network.py's
// MAX_MESSAGE_SIZE -- browsers have no equivalent client-side frame cap to set.
export const MAX_MESSAGE_SIZE = 20 * 1024 * 1024
