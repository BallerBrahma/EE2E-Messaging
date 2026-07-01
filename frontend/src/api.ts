// Thin typed wrapper over window.pywebview.api.* (the Python bridge defined
// in client/api.py) plus the push-event subscription used for live
// messages/presence/group changes. Keeps snake_case (Python) on one side of
// this file and camelCase (frontend convention) on the other.
//
// This file also doubles as the desktop-vs-web runtime facade -- see
// `bridge()` below -- so the web build (no pywebview bridge available) can
// transparently use `engine/webApi.ts` instead, with zero change to any
// component that calls `Api.*`.

import { webApi } from './engine/webApi'

export interface StoredMessage {
  conversation_id: string
  message_id: string
  sender_username: string | null
  direction: 'sent' | 'received'
  kind: 'text' | 'attachment' | 'system'
  body: Record<string, any>
  timestamp: number
}

export interface ConversationSummary {
  conversation_id: string
  kind: 'dm' | 'group'
  display_name: string
  last_preview: string
  last_timestamp: number
  pinned: boolean
}

export interface BackendEvent {
  type:
    | 'message'
    | 'delete'
    | 'group_invite'
    | 'group_member_added'
    | 'group_member_removed'
    | 'avatar_update'
    | 'presence'
    | 'presence_snapshot'
    | 'error'
  conversation_id?: string
  sender?: string
  timestamp?: number
  message_id?: string | null
  message_kind?: string | null
  body?: Record<string, any>
  username?: string
  online?: boolean
  online_usernames?: string[]
  message?: string
}

export interface PywebviewApi {
  has_local_identity(username: string): Promise<boolean>
  register(server: string, username: string, password: string): Promise<{ username: string; recovery_phrase: string }>
  login(server: string, username: string, password: string): Promise<{ username: string }>
  recover_account(server: string, username: string, recoveryPhrase: string, newPassword: string): Promise<{ username: string }>
  current_username(): Promise<string>
  has_biometric_support(): Promise<boolean>
  get_remembered_username(): Promise<string | null>
  remember_credentials(username: string, password: string): Promise<void>
  forget_remembered_login(): Promise<void>
  login_with_biometrics(server: string): Promise<{ username: string }>
  online_usernames(): Promise<string[]>
  list_conversations(): Promise<ConversationSummary[]>
  get_history(conversationId: string): Promise<StoredMessage[]>
  contacts(): Promise<string[]>
  group_members(groupId: string): Promise<string[]>
  group_name(groupId: string): Promise<string | null>
  is_pinned(conversationId: string): Promise<boolean>
  set_pinned(conversationId: string, pinned: boolean): Promise<void>
  add_contact(username: string): Promise<void>
  send_text(conversationId: string, text: string): Promise<string>
  send_attachment(conversationId: string, filename: string, mime: string, dataB64: string): Promise<string>
  delete_message(conversationId: string, messageId: string): Promise<void>
  create_group(name: string, members: string[]): Promise<string>
  add_group_member(groupId: string, username: string): Promise<void>
  remove_group_member(groupId: string, username: string): Promise<void>
  get_avatar(username: string): Promise<string | null>
  set_profile_picture(dataB64: string, mime: string): Promise<void>
  is_misspelled(word: string): Promise<boolean>
  spelling_suggestions(word: string): Promise<string[]>
  autocorrect_word(word: string): Promise<string | null>
  close(): Promise<void>
}

declare global {
  interface Window {
    pywebview?: { api: PywebviewApi }
    __onBackendEvent?: (event: BackendEvent) => void
  }
}

// Runtime facade: the desktop build (pywebview) exposes a Python-backed
// bridge at `window.pywebview.api`; the GitHub Pages web build has no such
// bridge, so it falls back to the browser-native engine in
// `engine/webApi.ts` instead. Both implement the exact same PywebviewApi
// shape, so nothing above this file (any React component) needs to know or
// care which one is in play.
function bridge(): PywebviewApi {
  if (window.pywebview) return window.pywebview.api
  return webApi
}

export const Api = {
  hasLocalIdentity: (username: string) => bridge().has_local_identity(username),
  register: (server: string, username: string, password: string) => bridge().register(server, username, password),
  login: (server: string, username: string, password: string) => bridge().login(server, username, password),
  recoverAccount: (server: string, username: string, recoveryPhrase: string, newPassword: string) =>
    bridge().recover_account(server, username, recoveryPhrase, newPassword),
  currentUsername: () => bridge().current_username(),
  hasBiometricSupport: () => bridge().has_biometric_support(),
  getRememberedUsername: () => bridge().get_remembered_username(),
  rememberCredentials: (username: string, password: string) => bridge().remember_credentials(username, password),
  forgetRememberedLogin: () => bridge().forget_remembered_login(),
  loginWithBiometrics: (server: string) => bridge().login_with_biometrics(server),
  onlineUsernames: () => bridge().online_usernames(),
  listConversations: () => bridge().list_conversations(),
  getHistory: (conversationId: string) => bridge().get_history(conversationId),
  contacts: () => bridge().contacts(),
  groupMembers: (groupId: string) => bridge().group_members(groupId),
  groupName: (groupId: string) => bridge().group_name(groupId),
  isPinned: (conversationId: string) => bridge().is_pinned(conversationId),
  setPinned: (conversationId: string, pinned: boolean) => bridge().set_pinned(conversationId, pinned),
  addContact: (username: string) => bridge().add_contact(username),
  sendText: (conversationId: string, text: string) => bridge().send_text(conversationId, text),
  sendAttachment: (conversationId: string, filename: string, mime: string, dataB64: string) =>
    bridge().send_attachment(conversationId, filename, mime, dataB64),
  deleteMessage: (conversationId: string, messageId: string) => bridge().delete_message(conversationId, messageId),
  createGroup: (name: string, members: string[]) => bridge().create_group(name, members),
  addGroupMember: (groupId: string, username: string) => bridge().add_group_member(groupId, username),
  removeGroupMember: (groupId: string, username: string) => bridge().remove_group_member(groupId, username),
  getAvatar: (username: string) => bridge().get_avatar(username),
  setProfilePicture: (dataB64: string, mime: string) => bridge().set_profile_picture(dataB64, mime),
  isMisspelled: (word: string) => bridge().is_misspelled(word),
  spellingSuggestions: (word: string) => bridge().spelling_suggestions(word),
  autocorrectWord: (word: string) => bridge().autocorrect_word(word),
  close: () => bridge().close(),
}

// How long to wait for `pywebviewready` before concluding we're not running
// inside pywebview at all (i.e. this is the plain-browser web build) and
// should proceed with the browser-native engine instead of waiting forever
// for an event that will never fire. Generous relative to how fast
// pywebview actually injects the bridge in practice.
const PYWEBVIEW_DETECT_TIMEOUT_MS = 500

/** Resolves once it's safe to start using `Api.*` -- either
 * `window.pywebview.api` becomes available (desktop build; pywebview
 * injects it asynchronously after the page loads and fires this event), or
 * a short timeout elapses with no such event (web build, no pywebview
 * bridge ever coming). */
export function onPywebviewReady(callback: () => void): void {
  if (window.pywebview) {
    callback()
    return
  }
  let settled = false
  const finish = () => {
    if (settled) return
    settled = true
    callback()
  }
  window.addEventListener('pywebviewready', finish, { once: true })
  setTimeout(finish, PYWEBVIEW_DETECT_TIMEOUT_MS)
}

/** Subscribe to backend push events (new messages, presence, group/avatar
 * changes). Returns an unsubscribe function. */
export function subscribeToBackendEvents(handler: (event: BackendEvent) => void): () => void {
  window.__onBackendEvent = handler
  return () => {
    if (window.__onBackendEvent === handler) {
      window.__onBackendEvent = undefined
    }
  }
}
