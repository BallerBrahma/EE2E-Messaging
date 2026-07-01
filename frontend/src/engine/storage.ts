// Local, encrypted-at-rest storage for a single client identity --
// TypeScript port of client/storage.py, backed by IndexedDB (via the `idb`
// promise wrapper) instead of SQLite. One IndexedDB database per username,
// object stores mirroring the SQLite tables 1:1.
//
// Everything sensitive (the identity/prekey private keys, per-conversation
// ratchet session state, message history, and a server-auth token -- see
// below) is stored encrypted with a random 256-bit **master key (MK)**. MK
// itself is never stored in the clear; it's wrapped ("envelope encrypted")
// twice: once by a KEK derived from the user's login password (Scrypt), and
// once by a KEK derived from a 12-word BIP39 recovery phrase (via
// `@scure/bip39`) generated once at account creation and shown to the user
// exactly once. Either factor independently unlocks MK -- this is the same
// pattern password managers use for recovery kits. Losing *both* the
// password and the recovery phrase means losing access, by design; losing
// just one is recoverable via the other (see `unlockWithRecovery` and
// `rotatePassword`).
//
// The **server-auth token** is a second thing worth calling out: it's a
// random value (unrelated to the human password) generated at account
// creation and stored MK-encrypted like everything else, then used as the
// "password" sent to the relay server's login. This means the server never
// sees anything derived from the user's real password, and password
// recovery never needs any server-side coordination -- recovering MK via
// the recovery phrase recovers the server-auth token too.
//
// Conversations are addressed by a single `conversationId` string:
// - a bare username (e.g. "bob") for a 1:1 conversation
// - "group:<uuid>" for a group conversation

import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { type IDBPDatabase, openDB } from 'idb'
import { utf8Decode, utf8Encode } from './crypto/encoding'
import { type KeyStore, generateKeyStore, keyStoreFromJson, keyStoreToJson } from './crypto/identity'
import * as prim from './crypto/primitives'
import { type RatchetState, ratchetStateFromJson, ratchetStateToJson } from './crypto/ratchet'

export const GROUP_PREFIX = 'group:'
const MASTER_KEY_LEN = 32
const SERVER_TOKEN_LEN = 32
const RECOVERY_HKDF_INFO = new TextEncoder().encode('E2EE-recovery-kek-v1')
const DB_VERSION = 1

export interface StoredMessage {
  conversationId: string
  messageId: string
  senderUsername: string | null
  direction: 'sent' | 'received'
  kind: string
  body: Record<string, unknown>
  timestamp: number
}

export interface ConversationSummary {
  conversationId: string
  kind: 'dm' | 'group'
  displayName: string
  lastPreview: string
  lastTimestamp: number
  pinned: boolean
}

export class WrongPassword extends Error {}
export class InvalidRecoveryPhrase extends Error {}

export function groupConversationId(groupId: string): string {
  return `${GROUP_PREFIX}${groupId}`
}

export function isGroupConversation(conversationId: string): boolean {
  return conversationId.startsWith(GROUP_PREFIX)
}

export function dbNameFor(username: string): string {
  const safe = Array.from(username)
    .filter((c) => /[a-zA-Z0-9_-]/.test(c))
    .join('')
  return `e2ee_client_${safe || 'user'}`
}

function openDatabase(username: string): Promise<IDBPDatabase> {
  return openDB(dbNameFor(username), DB_VERSION, {
    upgrade(db) {
      db.createObjectStore('meta', { keyPath: 'key' })
      db.createObjectStore('contacts', { keyPath: 'username' })
      db.createObjectStore('sessions', { keyPath: 'contactUsername' })
      db.createObjectStore('groups', { keyPath: 'groupId' })
      const groupMembers = db.createObjectStore('groupMembers', { keyPath: ['groupId', 'username'] })
      groupMembers.createIndex('byGroupId', 'groupId')
      db.createObjectStore('conversationSettings', { keyPath: 'conversationId' })
      db.createObjectStore('avatars', { keyPath: 'username' })
      const messages = db.createObjectStore('messages', { keyPath: 'id', autoIncrement: true })
      messages.createIndex('byConversationId', 'conversationId')
    },
  })
}

export class LocalStorage {
  private db: IDBPDatabase
  private encKey: Uint8Array | null = null

  private constructor(db: IDBPDatabase) {
    this.db = db
  }

  static async open(username: string): Promise<LocalStorage> {
    return new LocalStorage(await openDatabase(username))
  }

  // -- lifecycle --------------------------------------------------------------

  async isInitialized(): Promise<boolean> {
    return (await this.loadMeta('keystore')) !== undefined
  }

  /** Returns { keystore, recoveryPhrase }. The recovery phrase is only ever
   * available here, right after generation -- show it to the user once; it
   * isn't retrievable again after this call returns. */
  async createIdentity(username: string, password: string): Promise<{ keystore: KeyStore; recoveryPhrase: string }> {
    if (await this.isInitialized()) throw new Error('local storage already has an identity')

    const masterKey = prim.randomBytes(MASTER_KEY_LEN)
    const recoveryPhrase = generateMnemonic(wordlist, 128)
    const serverAuthToken = toHex(prim.randomBytes(SERVER_TOKEN_LEN))

    const passwordSalt = prim.newSalt()
    const passwordKek = await prim.deriveKeyFromPassword(password, passwordSalt)
    const recoveryKek = this.recoveryKek(recoveryPhrase)

    this.encKey = masterKey // unlocked from here on, so saveKeystore below works
    const keystore = generateKeyStore(username)

    await this.saveMeta('password_salt', passwordSalt)
    await this.saveMeta('wrapped_mk_password', prim.aeadEncrypt(passwordKek, masterKey))
    await this.saveMeta('wrapped_mk_recovery', prim.aeadEncrypt(recoveryKek, masterKey))
    await this.saveMeta('encrypted_server_token', prim.aeadEncrypt(masterKey, utf8Encode(serverAuthToken)))
    await this.saveKeystore(keystore)

    return { keystore, recoveryPhrase }
  }

  private recoveryKek(recoveryPhrase: string): Uint8Array {
    if (!validateMnemonic(recoveryPhrase, wordlist)) {
      throw new InvalidRecoveryPhrase('recovery phrase is invalid (misspelled word or wrong order)')
    }
    const entropy = mnemonicToEntropy(recoveryPhrase, wordlist)
    return prim.hkdf(entropy, MASTER_KEY_LEN, undefined, RECOVERY_HKDF_INFO)
  }

  /** Returns { keystore, serverAuthToken }. */
  async unlock(password: string): Promise<{ keystore: KeyStore; serverAuthToken: string }> {
    const passwordSalt = await this.loadMeta('password_salt')
    if (passwordSalt === undefined) throw new Error('local storage has no identity yet -- call createIdentity')
    const passwordKek = await prim.deriveKeyFromPassword(password, passwordSalt)
    const wrapped = await this.loadMetaRequired('wrapped_mk_password')
    let masterKey: Uint8Array
    try {
      masterKey = prim.aeadDecrypt(passwordKek, wrapped)
    } catch (exc) {
      if (exc instanceof prim.DecryptionError) throw new WrongPassword('incorrect password')
      throw exc
    }
    return this.finishUnlock(masterKey)
  }

  /** Returns { keystore, serverAuthToken }. Raises InvalidRecoveryPhrase for
   * a malformed/mistyped phrase (checksum failure, caught before any
   * decryption is attempted) or a well-formed phrase that simply doesn't
   * belong to this account (decryption failure). */
  async unlockWithRecovery(recoveryPhrase: string): Promise<{ keystore: KeyStore; serverAuthToken: string }> {
    const recoveryKek = this.recoveryKek(recoveryPhrase)
    const wrappedMk = await this.loadMeta('wrapped_mk_recovery')
    if (wrappedMk === undefined) throw new Error('local storage has no identity yet -- call createIdentity')
    let masterKey: Uint8Array
    try {
      masterKey = prim.aeadDecrypt(recoveryKek, wrappedMk)
    } catch (exc) {
      if (exc instanceof prim.DecryptionError) throw new InvalidRecoveryPhrase('recovery phrase does not match this account')
      throw exc
    }
    return this.finishUnlock(masterKey)
  }

  private async finishUnlock(masterKey: Uint8Array): Promise<{ keystore: KeyStore; serverAuthToken: string }> {
    this.encKey = masterKey
    const keystoreBlob = await this.loadMetaRequired('keystore')
    const keystore = keyStoreFromJson(JSON.parse(utf8Decode(prim.aeadDecrypt(masterKey, keystoreBlob))))
    const tokenBlob = await this.loadMetaRequired('encrypted_server_token')
    const serverAuthToken = utf8Decode(prim.aeadDecrypt(masterKey, tokenBlob))
    return { keystore, serverAuthToken }
  }

  /** Re-wraps the (already unlocked) master key under a new password.
   * Doesn't touch the master key itself, the recovery-phrase wrapping, or
   * any encrypted data -- the recovery phrase keeps working after a
   * password reset, same as a password manager's recovery kit. */
  async rotatePassword(newPassword: string): Promise<void> {
    const masterKey = this.requireUnlocked()
    const passwordSalt = prim.newSalt()
    const passwordKek = await prim.deriveKeyFromPassword(newPassword, passwordSalt)
    await this.saveMeta('password_salt', passwordSalt)
    await this.saveMeta('wrapped_mk_password', prim.aeadEncrypt(passwordKek, masterKey))
  }

  private requireUnlocked(): Uint8Array {
    if (this.encKey === null) throw new Error('storage is locked -- call createIdentity() or unlock() first')
    return this.encKey
  }

  /** The relay-login token for the currently unlocked identity (see module
   * docstring). Needed after createIdentity(), which doesn't return it
   * directly since unlock()/unlockWithRecovery() already do. */
  async serverAuthToken(): Promise<string> {
    const masterKey = this.requireUnlocked()
    const tokenBlob = await this.loadMetaRequired('encrypted_server_token')
    return utf8Decode(prim.aeadDecrypt(masterKey, tokenBlob))
  }

  // -- meta / keystore ----------------------------------------------------------

  private async saveMeta(key: string, value: Uint8Array): Promise<void> {
    await this.db.put('meta', { key, value })
  }

  private async loadMeta(key: string): Promise<Uint8Array | undefined> {
    const row = await this.db.get('meta', key)
    return row?.value
  }

  private async loadMetaRequired(key: string): Promise<Uint8Array> {
    const value = await this.loadMeta(key)
    if (value === undefined) throw new Error(`missing meta key: ${key}`)
    return value
  }

  /** Persist updated keystore state (e.g. after topping up one-time prekeys). */
  async saveKeystore(keystore: KeyStore): Promise<void> {
    const key = this.requireUnlocked()
    const plaintext = utf8Encode(JSON.stringify(keyStoreToJson(keystore)))
    await this.saveMeta('keystore', prim.aeadEncrypt(key, plaintext))
  }

  // -- contacts -------------------------------------------------------------------

  async addContact(username: string): Promise<void> {
    const existing = await this.db.get('contacts', username)
    if (existing === undefined) {
      await this.db.put('contacts', { username, addedAt: Date.now() / 1000 })
    }
  }

  async listContacts(): Promise<string[]> {
    const rows = await this.db.getAll('contacts')
    rows.sort((a, b) => a.addedAt - b.addedAt)
    return rows.map((r) => r.username)
  }

  // -- groups ---------------------------------------------------------------------

  async createGroup(groupId: string, name: string, members: string[]): Promise<void> {
    const tx = this.db.transaction(['groups', 'groupMembers'], 'readwrite')
    const groups = tx.objectStore('groups')
    const groupMembers = tx.objectStore('groupMembers')
    const existing = await groups.get(groupId)
    if (existing === undefined) {
      await groups.put({ groupId, name, createdAt: Date.now() / 1000 })
    }
    for (const member of members) {
      await groupMembers.put({ groupId, username: member })
    }
    await tx.done
  }

  async groupName(groupId: string): Promise<string | null> {
    const row = await this.db.get('groups', groupId)
    return row ? row.name : null
  }

  async groupMembers(groupId: string): Promise<string[]> {
    const rows = await this.db.getAllFromIndex('groupMembers', 'byGroupId', groupId)
    return rows.map((r) => r.username).sort()
  }

  async listGroups(): Promise<[string, string][]> {
    const rows = await this.db.getAll('groups')
    rows.sort((a, b) => a.createdAt - b.createdAt)
    return rows.map((r) => [r.groupId, r.name])
  }

  async addGroupMember(groupId: string, username: string): Promise<void> {
    await this.db.put('groupMembers', { groupId, username })
  }

  async removeGroupMember(groupId: string, username: string): Promise<void> {
    await this.db.delete('groupMembers', [groupId, username])
  }

  // -- ratchet sessions (always per-username, even for group conversations) --------

  async saveSession(contactUsername: string, state: RatchetState): Promise<void> {
    const key = this.requireUnlocked()
    const plaintext = utf8Encode(JSON.stringify(ratchetStateToJson(state)))
    const blob = prim.aeadEncrypt(key, plaintext)
    await this.db.put('sessions', { contactUsername, encryptedState: blob })
  }

  async loadSession(contactUsername: string): Promise<RatchetState | null> {
    const key = this.requireUnlocked()
    const row = await this.db.get('sessions', contactUsername)
    if (row === undefined) return null
    const plaintext = prim.aeadDecrypt(key, row.encryptedState)
    return ratchetStateFromJson(JSON.parse(utf8Decode(plaintext)))
  }

  // -- pinned conversations -----------------------------------------------------------

  async setPinned(conversationId: string, pinned: boolean): Promise<void> {
    await this.db.put('conversationSettings', { conversationId, pinned })
  }

  async isPinned(conversationId: string): Promise<boolean> {
    const row = await this.db.get('conversationSettings', conversationId)
    return row ? row.pinned : false
  }

  // -- avatars ----------------------------------------------------------------------

  async setAvatar(username: string, imageBytes: Uint8Array): Promise<void> {
    const key = this.requireUnlocked()
    const blob = prim.aeadEncrypt(key, imageBytes)
    await this.db.put('avatars', { username, encryptedImage: blob, updatedAt: Date.now() / 1000 })
  }

  async getAvatar(username: string): Promise<Uint8Array | null> {
    const key = this.requireUnlocked()
    const row = await this.db.get('avatars', username)
    if (row === undefined) return null
    return prim.aeadDecrypt(key, row.encryptedImage)
  }

  // -- message history ---------------------------------------------------------------

  private encryptBody(body: Record<string, unknown>): Uint8Array {
    const key = this.requireUnlocked()
    return prim.aeadEncrypt(key, utf8Encode(JSON.stringify(body)))
  }

  private decryptBody(blob: Uint8Array): Record<string, unknown> {
    const key = this.requireUnlocked()
    return JSON.parse(utf8Decode(prim.aeadDecrypt(key, blob)))
  }

  async addMessage(
    conversationId: string,
    senderUsername: string | null,
    direction: 'sent' | 'received',
    kind: string,
    messageId: string,
    body: Record<string, unknown>,
    timestamp?: number,
  ): Promise<void> {
    const ts = timestamp ?? Date.now() / 1000
    const blob = this.encryptBody(body)
    await this.db.add('messages', {
      conversationId,
      messageId,
      senderUsername,
      direction,
      kind,
      encryptedBody: blob,
      timestamp: ts,
      deleted: false,
    })
  }

  async getMessages(conversationId: string): Promise<StoredMessage[]> {
    const rows = await this.db.getAllFromIndex('messages', 'byConversationId', conversationId)
    return rows
      .filter((r) => !r.deleted)
      .sort((a, b) => a.timestamp - b.timestamp)
      .map((row) => ({
        conversationId,
        messageId: row.messageId,
        senderUsername: row.senderUsername,
        direction: row.direction,
        kind: row.kind,
        body: this.decryptBody(row.encryptedBody),
        timestamp: row.timestamp,
      }))
  }

  async markDeleted(conversationId: string, messageId: string): Promise<boolean> {
    const tx = this.db.transaction('messages', 'readwrite')
    const index = tx.store.index('byConversationId')
    let found = false
    for await (const cursor of index.iterate(conversationId)) {
      if (cursor.value.messageId === messageId) {
        found = true
        await cursor.update({ ...cursor.value, deleted: true })
      }
    }
    await tx.done
    return found
  }

  // -- conversation list (sidebar) ---------------------------------------------------

  async listConversations(): Promise<ConversationSummary[]> {
    const summaries = new Map<string, ConversationSummary>()
    for (const username of await this.listContacts()) {
      summaries.set(username, { conversationId: username, kind: 'dm', displayName: username, lastPreview: '', lastTimestamp: 0, pinned: false })
    }
    for (const [groupId, name] of await this.listGroups()) {
      const cid = groupConversationId(groupId)
      summaries.set(cid, { conversationId: cid, kind: 'group', displayName: name, lastPreview: '', lastTimestamp: 0, pinned: false })
    }

    const allMessages = await this.db.getAll('messages')
    const nonDeleted = allMessages.filter((r) => !r.deleted).sort((a, b) => a.timestamp - b.timestamp)
    for (const row of nonDeleted) {
      const existing = summaries.get(row.conversationId)
      if (existing === undefined) continue // orphaned message with no contact/group record (shouldn't normally happen)
      const body = this.decryptBody(row.encryptedBody)
      const preview = previewText(row.kind, body)
      summaries.set(row.conversationId, { ...existing, lastPreview: preview, lastTimestamp: row.timestamp })
    }

    const settingsRows = await this.db.getAll('conversationSettings')
    const pinnedIds = new Set(settingsRows.filter((r) => r.pinned).map((r) => r.conversationId))
    for (const [cid, summary] of summaries) {
      summaries.set(cid, { ...summary, pinned: pinnedIds.has(cid) })
    }

    return Array.from(summaries.values()).sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1
      return b.lastTimestamp - a.lastTimestamp
    })
  }
}

function previewText(kind: string, body: Record<string, unknown>): string {
  if (kind === 'text') return (body.content as string) ?? ''
  if (kind === 'attachment') return `\u{1F4CE} ${(body.filename as string) ?? 'attachment'}`
  if (kind === 'system') return (body.content as string) ?? ''
  return ''
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
