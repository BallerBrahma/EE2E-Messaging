// Browser-native implementation of the PywebviewApi surface -- backs the
// GitHub Pages web build. Selected at runtime by api.ts's facade when
// `window.pywebview` isn't present (see that file). This is the browser
// counterpart to client/api.py: same public surface, same event-bus
// mechanism (`window.__onBackendEvent`, called directly here instead of via
// pywebview's `evaluate_js`), but backed by engine/{storage,network,
// sessionManager}.ts instead of a Python bridge.
//
// Touch ID/Keychain "remember me" has no browser equivalent (see the plan's
// "Feature parity" section) -- those methods are harmless stubs, and
// `has_biometric_support` always returning `false` means LoginScreen.tsx's
// biometric UI branch simply never renders here, with no UI code change
// needed. The spellcheck/autocorrect methods are backed by engine/
// spellcheck.ts (nspell + dictionary-en), a real port of client/
// spellcheck.py -- not a stub.

import type { BackendEvent, ConversationSummary, PywebviewApi, StoredMessage } from '../api'
import { fromBase64, toBase64 } from './crypto/encoding'
import type { KeyStore } from './crypto/identity'
import { NetworkClient } from './network'
import { type IncomingEvent, SessionManager } from './sessionManager'
import { InvalidRecoveryPhrase, LocalStorage, WrongPassword, dbNameFor } from './storage'

interface ActiveSession {
  storage: LocalStorage
  network: NetworkClient
  manager: SessionManager
}

let session: ActiveSession | null = null
let onlineUsernameSet = new Set<string>()

function emit(event: BackendEvent): void {
  // `window` is always present in the real deployed (browser) environment --
  // this guard exists only so the engine test suite can run under a plain
  // Node environment (no DOM) without pulling in jsdom for the whole suite.
  if (typeof window !== 'undefined') window.__onBackendEvent?.(event)
}

function eventFromIncoming(event: IncomingEvent): BackendEvent {
  return {
    type: event.kind,
    conversation_id: event.conversationId,
    sender: event.sender,
    timestamp: event.timestamp,
    message_id: event.messageId ?? null,
    message_kind: event.messageKind ?? null,
    body: event.body,
  }
}

function requireSession(): ActiveSession {
  if (session === null) throw new Error('not logged in')
  return session
}

function attachSession(next: ActiveSession): void {
  session = next
  onlineUsernameSet = new Set()
  next.network.onMessage = async (incoming) => {
    try {
      const event = await next.manager.handleIncoming(incoming)
      emit(eventFromIncoming(event))
    } catch (exc) {
      emit({ type: 'error', message: `failed to process message from ${incoming.sender}: ${exc}` })
    }
  }
  next.network.onPresence = (username, online) => {
    if (online) onlineUsernameSet.add(username)
    else onlineUsernameSet.delete(username)
    emit({ type: 'presence', username, online })
  }
  next.network.onPresenceSnapshot = (usernames) => {
    onlineUsernameSet = new Set(usernames)
    emit({ type: 'presence_snapshot', online_usernames: usernames })
  }
}

async function connectAndAttach(server: string, keystore: KeyStore, storage: LocalStorage): Promise<ActiveSession> {
  const network = new NetworkClient(server)
  const manager = new SessionManager(keystore, storage, network)
  const next: ActiveSession = { storage, network, manager }
  attachSession(next) // wire push-event callbacks before connecting -- the server
  // pushes presence_snapshot and any pending offline messages in the same burst as
  // the login response, so callbacks must already be set or those get dropped.
  await network.connect()
  return next
}

async function bootstrapLogin(server: string, username: string, serverAuthToken: string, keystore: KeyStore, storage: LocalStorage): Promise<void> {
  const active = await connectAndAttach(server, keystore, storage)
  await active.network.login(username, serverAuthToken)
  await active.manager.publishKeys()
}

// -- account ------------------------------------------------------------------------

async function hasLocalIdentity(username: string): Promise<boolean> {
  const name = dbNameFor(username)
  const dbs = await indexedDB.databases()
  return dbs.some((d) => d.name === name)
}

async function register(server: string, username: string, password: string): Promise<{ username: string; recovery_phrase: string }> {
  const storage = await LocalStorage.open(username)
  const { keystore, recoveryPhrase } = await storage.createIdentity(username, password)
  const serverAuthToken = await storage.serverAuthToken()
  const active = await connectAndAttach(server, keystore, storage)
  await active.network.register(username, serverAuthToken) // new account only -- login/recover never re-register
  await active.network.login(username, serverAuthToken)
  await active.manager.publishKeys()
  return { username, recovery_phrase: recoveryPhrase }
}

async function login(server: string, username: string, password: string): Promise<{ username: string }> {
  const storage = await LocalStorage.open(username)
  const unlocked = await unlockOrThrow(storage, password)
  await bootstrapLogin(server, username, unlocked.serverAuthToken, unlocked.keystore, storage)
  return { username }
}

async function unlockOrThrow(storage: LocalStorage, password: string): Promise<{ keystore: KeyStore; serverAuthToken: string }> {
  try {
    return await storage.unlock(password)
  } catch (exc) {
    if (exc instanceof WrongPassword) throw new Error('incorrect password')
    throw exc
  }
}

async function recoverAccount(server: string, username: string, recoveryPhrase: string, newPassword: string): Promise<{ username: string }> {
  const storage = await LocalStorage.open(username)
  const unlocked = await unlockRecoveryOrThrow(storage, recoveryPhrase)
  await storage.rotatePassword(newPassword)
  await bootstrapLogin(server, username, unlocked.serverAuthToken, unlocked.keystore, storage)
  return { username }
}

async function unlockRecoveryOrThrow(storage: LocalStorage, recoveryPhrase: string): Promise<{ keystore: KeyStore; serverAuthToken: string }> {
  try {
    return await storage.unlockWithRecovery(recoveryPhrase)
  } catch (exc) {
    if (exc instanceof InvalidRecoveryPhrase) throw new Error(exc.message)
    throw exc
  }
}

async function currentUsername(): Promise<string> {
  return requireSession().manager.username
}

// -- remember me / Touch ID -- no browser equivalent, see module docstring ----------

async function hasBiometricSupport(): Promise<boolean> {
  return false
}

async function getRememberedUsername(): Promise<string | null> {
  return null
}

async function rememberCredentials(): Promise<void> {}

async function forgetRememberedLogin(): Promise<void> {}

async function loginWithBiometrics(): Promise<{ username: string }> {
  throw new Error('Touch ID / biometric login is not available in the web build')
}

// -- presence -------------------------------------------------------------------------

async function onlineUsernames(): Promise<string[]> {
  requireSession()
  return Array.from(onlineUsernameSet).sort()
}

// -- conversations / history ----------------------------------------------------------

async function listConversations(): Promise<ConversationSummary[]> {
  const summaries = await requireSession().manager.conversations()
  return summaries.map((s) => ({
    conversation_id: s.conversationId,
    kind: s.kind,
    display_name: s.displayName,
    last_preview: s.lastPreview,
    last_timestamp: s.lastTimestamp,
    pinned: s.pinned,
  }))
}

async function getHistory(conversationId: string): Promise<StoredMessage[]> {
  const messages = await requireSession().manager.history(conversationId)
  return messages.map((m) => ({
    conversation_id: m.conversationId,
    message_id: m.messageId,
    sender_username: m.senderUsername,
    direction: m.direction,
    kind: m.kind as StoredMessage['kind'],
    body: m.body,
    timestamp: m.timestamp,
  }))
}

async function contacts(): Promise<string[]> {
  return requireSession().manager.contacts()
}

async function groupMembers(groupId: string): Promise<string[]> {
  return requireSession().storage.groupMembers(groupId)
}

async function groupName(groupId: string): Promise<string | null> {
  return requireSession().storage.groupName(groupId)
}

async function isPinned(conversationId: string): Promise<boolean> {
  return requireSession().storage.isPinned(conversationId)
}

async function setPinned(conversationId: string, pinned: boolean): Promise<void> {
  await requireSession().manager.setPinned(conversationId, pinned)
}

async function addContact(username: string): Promise<void> {
  await requireSession().storage.addContact(username)
}

// -- sending ---------------------------------------------------------------------------

async function sendText(conversationId: string, text: string): Promise<string> {
  return requireSession().manager.sendText(conversationId, text)
}

async function sendAttachment(conversationId: string, filename: string, mime: string, dataB64: string): Promise<string> {
  const data = fromBase64(dataB64)
  return requireSession().manager.sendAttachment(conversationId, filename, mime, data)
}

async function deleteMessage(conversationId: string, messageId: string): Promise<void> {
  await requireSession().manager.deleteMessage(conversationId, messageId)
}

// -- groups -----------------------------------------------------------------------------

async function createGroup(name: string, members: string[]): Promise<string> {
  return requireSession().manager.createGroup(name, members)
}

async function addGroupMember(groupId: string, username: string): Promise<void> {
  await requireSession().manager.addGroupMember(groupId, username)
}

async function removeGroupMember(groupId: string, username: string): Promise<void> {
  await requireSession().manager.removeGroupMember(groupId, username)
}

// -- avatars ----------------------------------------------------------------------------

async function getAvatar(username: string): Promise<string | null> {
  const data = await requireSession().manager.avatar(username)
  if (data === null) return null
  return `data:image/png;base64,${toBase64(data)}`
}

async function setProfilePicture(dataB64: string, mime: string): Promise<void> {
  const data = fromBase64(dataB64)
  await requireSession().manager.setProfilePicture(data, mime)
}

// -- spellcheck / autocorrect ------------------------------------------------------------

// Lazy-loaded: the dictionary data is a few hundred KB, and nobody needs it
// before they've logged in and started typing a message -- code-splitting
// it out keeps that weight off the initial page load for every visitor.
let spellcheckModulePromise: Promise<typeof import('./spellcheck')> | null = null
function loadSpellcheck(): Promise<typeof import('./spellcheck')> {
  if (spellcheckModulePromise === null) {
    spellcheckModulePromise = import('./spellcheck')
  }
  return spellcheckModulePromise
}

async function isMisspelled(word: string): Promise<boolean> {
  const spellcheck = await loadSpellcheck()
  return spellcheck.isMisspelled(word)
}

async function spellingSuggestions(word: string): Promise<string[]> {
  const spellcheck = await loadSpellcheck()
  return spellcheck.suggestions(word)
}

async function autocorrectWord(word: string): Promise<string | null> {
  const spellcheck = await loadSpellcheck()
  return spellcheck.autocorrectWord(word)
}

// -- lifecycle --------------------------------------------------------------------------

async function close(): Promise<void> {
  if (session !== null) {
    await session.network.close()
  }
}

export const webApi: PywebviewApi = {
  has_local_identity: hasLocalIdentity,
  register,
  login,
  recover_account: recoverAccount,
  current_username: currentUsername,
  has_biometric_support: hasBiometricSupport,
  get_remembered_username: getRememberedUsername,
  remember_credentials: rememberCredentials,
  forget_remembered_login: forgetRememberedLogin,
  login_with_biometrics: loginWithBiometrics,
  online_usernames: onlineUsernames,
  list_conversations: listConversations,
  get_history: getHistory,
  contacts,
  group_members: groupMembers,
  group_name: groupName,
  is_pinned: isPinned,
  set_pinned: setPinned,
  add_contact: addContact,
  send_text: sendText,
  send_attachment: sendAttachment,
  delete_message: deleteMessage,
  create_group: createGroup,
  add_group_member: addGroupMember,
  remove_group_member: removeGroupMember,
  get_avatar: getAvatar,
  set_profile_picture: setProfilePicture,
  is_misspelled: isMisspelled,
  spelling_suggestions: spellingSuggestions,
  autocorrect_word: autocorrectWord,
  close,
}
