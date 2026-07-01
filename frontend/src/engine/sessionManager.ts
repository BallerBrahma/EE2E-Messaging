// Ties crypto (X3DH + Double Ratchet) to local storage and the network --
// TypeScript port of client/session_manager.py.
//
// Every ratchet-encrypted plaintext is a small JSON "envelope" (see
// buildEnvelope call sites) rather than a raw string, which is what makes
// deletes, group messages and attachments possible on top of the same
// pairwise Double Ratchet sessions built for 1:1 chat. Group conversations
// are pure pairwise fan-out: one envelope (one id) gets encrypted separately
// to every other member's existing/newly-established 1:1 session -- there
// is no group-level cryptographic key.

import { utf8Decode, utf8Encode } from './crypto/encoding'
import { type KeyStore, topUpOneTimePrekeys } from './crypto/identity'
import { initAsInitiator, initAsResponder, ratchetDecrypt, ratchetEncrypt } from './crypto/ratchet'
import { initiate, respond } from './crypto/x3dh'
import { type IncomingMessage, type NetworkClient } from './network'
import {
  type ConversationSummary,
  type LocalStorage,
  type StoredMessage,
  groupConversationId,
  isGroupConversation,
} from './storage'

const ONE_TIME_PREKEY_TARGET = 20
const ATTACHMENT_MAX_BYTES = 10 * 1024 * 1024
const AVATAR_MAX_BYTES = 2 * 1024 * 1024

export type IncomingEventKind =
  | 'message'
  | 'delete'
  | 'group_invite'
  | 'group_member_added'
  | 'group_member_removed'
  | 'avatar_update'

export interface IncomingEvent {
  kind: IncomingEventKind
  conversationId: string
  sender: string
  timestamp: number
  messageId?: string | null
  messageKind?: string | null // "text" | "attachment" | "system", when kind === "message"
  body: Record<string, unknown>
}

function base64FromBytes(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

function bytesFromBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function envelopeBytes(envelope: Record<string, unknown>): Uint8Array {
  return utf8Encode(JSON.stringify(envelope))
}

function envelopeFromBytes(data: Uint8Array): Record<string, unknown> {
  return JSON.parse(utf8Decode(data))
}

type EnvelopeHandler = (
  manager: SessionManager,
  sender: string,
  conversationId: string,
  groupId: string | null,
  envelope: Record<string, unknown>,
  timestamp: number,
) => Promise<IncomingEvent>

export class SessionManager {
  readonly keystore: KeyStore
  readonly storage: LocalStorage
  readonly network: NetworkClient

  constructor(keystore: KeyStore, storage: LocalStorage, network: NetworkClient) {
    this.keystore = keystore
    this.storage = storage
    this.network = network
  }

  get username(): string {
    return this.keystore.username
  }

  /** Upload identity/signed-prekey/one-time-prekeys; top up if running low. */
  async publishKeys(): Promise<void> {
    if (topUpOneTimePrekeys(this.keystore, ONE_TIME_PREKEY_TARGET).length > 0) {
      await this.storage.saveKeystore(this.keystore)
    }
    await this.network.uploadKeys(this.keystore)
  }

  // -- recipient resolution --------------------------------------------------------

  private async recipientsFor(conversationId: string): Promise<string[]> {
    if (isGroupConversation(conversationId)) {
      const groupId = conversationId.split(':').slice(1).join(':')
      const members = await this.storage.groupMembers(groupId)
      return members.filter((m) => m !== this.username)
    }
    return [conversationId]
  }

  // -- low-level: encrypt+send one envelope to one recipient -----------------------

  private async sendEnvelopeTo(recipientUsername: string, envelope: Record<string, unknown>): Promise<void> {
    let session = await this.storage.loadSession(recipientUsername)
    let x3dhHeaderJson: Record<string, unknown> | null = null

    if (session === null) {
      const bundle = await this.network.fetchBundle(recipientUsername)
      if (bundle === null) {
        throw new Error(`no such user or no published keys: ${recipientUsername}`)
      }
      const { result, header } = initiate(this.keystore, bundle)
      session = initAsInitiator(result.sharedSecret, result.associatedData, bundle.signedPrekeyPub)
      x3dhHeaderJson = {
        initiator_identity_pub_dh: base64FromBytes(header.initiatorIdentityPubDh),
        initiator_ephemeral_pub: base64FromBytes(header.initiatorEphemeralPub),
        signed_prekey_id: header.signedPrekeyId,
        one_time_prekey_id: header.oneTimePrekeyId,
      }
    }

    const ratchetMessage = ratchetEncrypt(session, envelopeBytes(envelope))
    const payload = {
      x3dh_header: x3dhHeaderJson,
      ratchet_message: {
        header: {
          dh_pub: base64FromBytes(ratchetMessage.header.dhPub),
          pn: ratchetMessage.header.pn,
          n: ratchetMessage.header.n,
        },
        ciphertext: base64FromBytes(ratchetMessage.ciphertext),
      },
    }
    await this.network.sendMessage(recipientUsername, payload)
    await this.storage.saveSession(recipientUsername, session)
  }

  private async fanOut(conversationId: string, envelope: Record<string, unknown>): Promise<void> {
    for (const recipient of await this.recipientsFor(conversationId)) {
      await this.sendEnvelopeTo(recipient, envelope)
    }
  }

  private async requireGroupMembership(conversationId: string): Promise<void> {
    if (isGroupConversation(conversationId)) {
      const groupId = conversationId.split(':').slice(1).join(':')
      const members = await this.storage.groupMembers(groupId)
      if (!members.includes(this.username)) {
        throw new Error('you are no longer a member of this group')
      }
    }
  }

  private groupIdOf(conversationId: string): string | null {
    return isGroupConversation(conversationId) ? conversationId.split(':').slice(1).join(':') : null
  }

  // -- sending: text / attachment ---------------------------------------------------

  async sendText(conversationId: string, text: string): Promise<string> {
    await this.requireGroupMembership(conversationId)
    const messageId = crypto.randomUUID()
    const groupId = this.groupIdOf(conversationId)
    const envelope = { id: messageId, type: 'text', group_id: groupId, body: { content: text } }
    await this.fanOut(conversationId, envelope)

    if (!isGroupConversation(conversationId)) {
      await this.storage.addContact(conversationId)
    }
    await this.storage.addMessage(conversationId, this.username, 'sent', 'text', messageId, envelope.body, Date.now() / 1000)
    return messageId
  }

  async sendAttachment(conversationId: string, filename: string, mime: string, data: Uint8Array): Promise<string> {
    await this.requireGroupMembership(conversationId)
    if (data.length > ATTACHMENT_MAX_BYTES) {
      throw new Error(`attachment too large (${data.length} bytes, max ${ATTACHMENT_MAX_BYTES})`)
    }
    const messageId = crypto.randomUUID()
    const groupId = this.groupIdOf(conversationId)
    const body = { filename, mime, size: data.length, data_b64: base64FromBytes(data) }
    const envelope = { id: messageId, type: 'attachment', group_id: groupId, body }
    await this.fanOut(conversationId, envelope)

    if (!isGroupConversation(conversationId)) {
      await this.storage.addContact(conversationId)
    }
    await this.storage.addMessage(conversationId, this.username, 'sent', 'attachment', messageId, body, Date.now() / 1000)
    return messageId
  }

  // -- delete-for-everyone -----------------------------------------------------------

  async deleteMessage(conversationId: string, messageId: string): Promise<void> {
    await this.storage.markDeleted(conversationId, messageId)
    const groupId = this.groupIdOf(conversationId)
    const envelope = { id: crypto.randomUUID(), type: 'delete', group_id: groupId, body: { target_id: messageId } }
    await this.fanOut(conversationId, envelope)
  }

  // -- groups ---------------------------------------------------------------------------

  async createGroup(name: string, members: string[]): Promise<string> {
    const groupId = crypto.randomUUID()
    const allMembers = Array.from(new Set([...members, this.username])).sort()
    await this.storage.createGroup(groupId, name, allMembers)
    const conversationId = groupConversationId(groupId)

    const envelope = { id: crypto.randomUUID(), type: 'group_invite', group_id: groupId, body: { group_id: groupId, name, members: allMembers } }
    for (const member of allMembers) {
      if (member !== this.username) await this.sendEnvelopeTo(member, envelope)
    }

    await this.storage.addMessage(conversationId, null, 'sent', 'system', crypto.randomUUID(), { content: 'You created this group' }, Date.now() / 1000)
    return groupId
  }

  async groups(): Promise<[string, string][]> {
    return this.storage.listGroups()
  }

  async addGroupMember(groupId: string, username: string): Promise<void> {
    const conversationId = groupConversationId(groupId)
    const currentMembers = await this.storage.groupMembers(groupId)
    if (currentMembers.includes(username)) return
    await this.storage.addGroupMember(groupId, username)
    const newRoster = Array.from(new Set([...currentMembers, username])).sort()
    const name = (await this.storage.groupName(groupId)) ?? 'Unnamed group'

    const inviteEnvelope = { id: crypto.randomUUID(), type: 'group_invite', group_id: groupId, body: { group_id: groupId, name, members: newRoster } }
    await this.sendEnvelopeTo(username, inviteEnvelope)

    const addedEnvelope = { id: crypto.randomUUID(), type: 'group_member_added', group_id: groupId, body: { group_id: groupId, added_username: username } }
    for (const member of currentMembers) {
      if (member !== this.username) await this.sendEnvelopeTo(member, addedEnvelope)
    }

    await this.storage.addMessage(conversationId, null, 'sent', 'system', crypto.randomUUID(), { content: `You added ${username}` }, Date.now() / 1000)
  }

  async removeGroupMember(groupId: string, username: string): Promise<void> {
    const conversationId = groupConversationId(groupId)
    const oldRoster = await this.storage.groupMembers(groupId)
    if (!oldRoster.includes(username)) return
    await this.storage.removeGroupMember(groupId, username)

    const removedEnvelope = { id: crypto.randomUUID(), type: 'group_member_removed', group_id: groupId, body: { group_id: groupId, removed_username: username } }
    for (const member of oldRoster) {
      if (member !== this.username) await this.sendEnvelopeTo(member, removedEnvelope)
    }

    const note = username === this.username ? 'You left this group' : `You removed ${username}`
    await this.storage.addMessage(conversationId, null, 'sent', 'system', crypto.randomUUID(), { content: note }, Date.now() / 1000)
  }

  // -- profile pictures -------------------------------------------------------------------

  private async knownRecipients(): Promise<Set<string>> {
    const recipients = new Set(await this.storage.listContacts())
    for (const [groupId] of await this.storage.listGroups()) {
      for (const member of await this.storage.groupMembers(groupId)) recipients.add(member)
    }
    recipients.delete(this.username)
    return recipients
  }

  async setProfilePicture(imageBytes: Uint8Array, mime: string): Promise<void> {
    if (imageBytes.length > AVATAR_MAX_BYTES) {
      throw new Error(`image too large (${imageBytes.length} bytes, max ${AVATAR_MAX_BYTES})`)
    }
    await this.storage.setAvatar(this.username, imageBytes)
    const envelope = { id: crypto.randomUUID(), type: 'profile_picture', group_id: null, body: { image_b64: base64FromBytes(imageBytes), mime } }
    for (const recipient of await this.knownRecipients()) {
      await this.sendEnvelopeTo(recipient, envelope)
    }
  }

  async avatar(username: string): Promise<Uint8Array | null> {
    return this.storage.getAvatar(username)
  }

  // -- receiving ------------------------------------------------------------------------

  private async decryptEnvelope(incoming: IncomingMessage): Promise<Record<string, unknown>> {
    const sender = incoming.sender
    const payload = incoming.payload
    let session = await this.storage.loadSession(sender)

    if (payload.x3dh_header !== null && payload.x3dh_header !== undefined && session === null) {
      const headerJson = payload.x3dh_header as Record<string, unknown>
      const header = {
        initiatorIdentityPubDh: bytesFromBase64(headerJson.initiator_identity_pub_dh as string),
        initiatorEphemeralPub: bytesFromBase64(headerJson.initiator_ephemeral_pub as string),
        signedPrekeyId: headerJson.signed_prekey_id as string,
        oneTimePrekeyId: (headerJson.one_time_prekey_id as string | null) ?? null,
      }
      const result = respond(this.keystore, header)
      session = initAsResponder(result.sharedSecret, result.associatedData, this.keystore.signedPrekey.privateKey)
      // the one-time prekey consumed by respond() was removed from the
      // in-memory keystore -- persist that so it can't be reused.
      await this.storage.saveKeystore(this.keystore)
    }

    if (session === null) {
      throw new Error(`received a message from ${sender} with no session and no X3DH init header`)
    }

    const ratchetMessageJson = payload.ratchet_message as Record<string, unknown>
    const headerJson = ratchetMessageJson.header as Record<string, unknown>
    const ratchetMessage = {
      header: { dhPub: bytesFromBase64(headerJson.dh_pub as string), pn: headerJson.pn as number, n: headerJson.n as number },
      ciphertext: bytesFromBase64(ratchetMessageJson.ciphertext as string),
    }
    const envelope = envelopeFromBytes(ratchetDecrypt(session, ratchetMessage))
    await this.storage.saveSession(sender, session)
    return envelope
  }

  async handleIncoming(incoming: IncomingMessage): Promise<IncomingEvent> {
    const sender = incoming.sender
    const ts = incoming.createdAt
    const envelope = await this.decryptEnvelope(incoming)
    const envelopeType = envelope.type as string
    const groupId = (envelope.group_id as string | null) ?? null
    const conversationId = groupId ? groupConversationId(groupId) : sender

    const handler = ENVELOPE_HANDLERS[envelopeType]
    if (handler === undefined) {
      throw new Error(`unknown envelope type: ${envelopeType}`)
    }

    if (envelopeType !== 'group_invite' && envelopeType !== 'profile_picture' && groupId && !(await this.storage.groupName(groupId))) {
      // message for a group we don't know about yet (e.g. local state lost) --
      // degrade gracefully instead of dropping the message.
      await this.storage.createGroup(groupId, 'Unknown group', [sender, this.username])
    }

    return await handler(this, sender, conversationId, groupId, envelope, ts)
  }

  // -- read helpers -----------------------------------------------------------------------

  async history(conversationId: string): Promise<StoredMessage[]> {
    return this.storage.getMessages(conversationId)
  }

  async conversations(): Promise<ConversationSummary[]> {
    return this.storage.listConversations()
  }

  async contacts(): Promise<string[]> {
    return this.storage.listContacts()
  }

  async setPinned(conversationId: string, pinned: boolean): Promise<void> {
    // purely a local organizational preference -- not synced to the other side(s).
    await this.storage.setPinned(conversationId, pinned)
  }
}

async function onGroupInvite(manager: SessionManager, sender: string, _conversationId: string, _groupId: string | null, envelope: Record<string, unknown>, ts: number): Promise<IncomingEvent> {
  const body = envelope.body as Record<string, unknown>
  await manager.storage.createGroup(body.group_id as string, body.name as string, body.members as string[])
  return { kind: 'group_invite', conversationId: groupConversationId(body.group_id as string), sender, timestamp: ts, body }
}

async function onProfilePicture(manager: SessionManager, sender: string, _conversationId: string, _groupId: string | null, envelope: Record<string, unknown>, ts: number): Promise<IncomingEvent> {
  const body = envelope.body as Record<string, unknown>
  const imageBytes = bytesFromBase64(body.image_b64 as string)
  await manager.storage.setAvatar(sender, imageBytes)
  return { kind: 'avatar_update', conversationId: sender, sender, timestamp: ts, body }
}

async function onDelete(manager: SessionManager, sender: string, conversationId: string, _groupId: string | null, envelope: Record<string, unknown>, ts: number): Promise<IncomingEvent> {
  const body = envelope.body as Record<string, unknown>
  const targetId = body.target_id as string
  await manager.storage.markDeleted(conversationId, targetId)
  return { kind: 'delete', conversationId, sender, timestamp: ts, messageId: targetId, body }
}

async function onGroupMemberAdded(manager: SessionManager, sender: string, conversationId: string, groupId: string | null, envelope: Record<string, unknown>, ts: number): Promise<IncomingEvent> {
  const body = envelope.body as Record<string, unknown>
  const addedUsername = body.added_username as string
  await manager.storage.addGroupMember(groupId as string, addedUsername)
  await manager.storage.addMessage(conversationId, null, 'received', 'system', crypto.randomUUID(), { content: `${addedUsername} was added` }, ts)
  return { kind: 'group_member_added', conversationId, sender, timestamp: ts, body }
}

async function onGroupMemberRemoved(manager: SessionManager, sender: string, conversationId: string, groupId: string | null, envelope: Record<string, unknown>, ts: number): Promise<IncomingEvent> {
  const body = envelope.body as Record<string, unknown>
  const removedUsername = body.removed_username as string
  await manager.storage.removeGroupMember(groupId as string, removedUsername)
  const note = removedUsername === manager.username ? 'You were removed from the group' : `${removedUsername} was removed`
  await manager.storage.addMessage(conversationId, null, 'received', 'system', crypto.randomUUID(), { content: note }, ts)
  return { kind: 'group_member_removed', conversationId, sender, timestamp: ts, body }
}

async function onContentMessage(manager: SessionManager, sender: string, conversationId: string, _groupId: string | null, envelope: Record<string, unknown>, ts: number): Promise<IncomingEvent> {
  const envelopeType = envelope.type as string
  if (!isGroupConversation(conversationId)) {
    await manager.storage.addContact(sender)
  }
  const body = envelope.body as Record<string, unknown>
  await manager.storage.addMessage(conversationId, sender, 'received', envelopeType, envelope.id as string, body, ts)
  return { kind: 'message', conversationId, sender, timestamp: ts, messageId: envelope.id as string, messageKind: envelopeType, body }
}

const ENVELOPE_HANDLERS: Record<string, EnvelopeHandler> = {
  group_invite: onGroupInvite,
  profile_picture: onProfilePicture,
  delete: onDelete,
  group_member_added: onGroupMemberAdded,
  group_member_removed: onGroupMemberRemoved,
  text: onContentMessage,
  attachment: onContentMessage,
}
