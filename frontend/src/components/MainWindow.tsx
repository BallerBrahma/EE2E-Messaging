import { useCallback, useEffect, useState } from 'react'
import { Menu, PenSquare, Users } from 'lucide-react'
import Avatar from './Avatar'
import ConversationRow from './ConversationRow'
import ChatView from './ChatView'
import GroupCreateDialog from './GroupCreateDialog'
import GroupInfoDialog from './GroupInfoDialog'
import ThemeToggle from './ThemeToggle'
import { Api, subscribeToBackendEvents, type BackendEvent, type ConversationSummary } from '../api'

interface MainWindowProps {
  username: string
}

type Tab = 'dm' | 'group'

export default function MainWindow({ username }: MainWindowProps) {
  const [conversations, setConversations] = useState<ConversationSummary[]>([])
  const [activeTab, setActiveTab] = useState<Tab>('dm')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [onlineUsernames, setOnlineUsernames] = useState<Set<string>>(new Set())
  const [sidebarVisible, setSidebarVisible] = useState(true)
  const [ownAvatar, setOwnAvatar] = useState<string | null>(null)
  const [rowAvatars, setRowAvatars] = useState<Record<string, string | null>>({})
  const [contacts, setContacts] = useState<string[]>([])
  const [refreshSignal, setRefreshSignal] = useState(0)
  const [showNewChat, setShowNewChat] = useState(false)
  const [showGroupCreate, setShowGroupCreate] = useState(false)
  const [showGroupInfo, setShowGroupInfo] = useState(false)

  const refreshSidebar = useCallback(async () => {
    const list = await Api.listConversations()
    setConversations(list)
    const dmIds = list.filter((c) => c.kind === 'dm').map((c) => c.conversation_id)
    const avatarEntries = await Promise.all(dmIds.map(async (id) => [id, await Api.getAvatar(id)] as const))
    setRowAvatars(Object.fromEntries(avatarEntries))
  }, [])

  const refreshOwnAvatar = useCallback(async () => {
    setOwnAvatar(await Api.getAvatar(username))
  }, [username])

  useEffect(() => {
    refreshSidebar()
    refreshOwnAvatar()
    Api.onlineUsernames().then((list) => setOnlineUsernames(new Set(list)))
    Api.contacts().then(setContacts)
  }, [refreshSidebar, refreshOwnAvatar])

  useEffect(() => {
    return subscribeToBackendEvents((event: BackendEvent) => handleBackendEvent(event))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function handleBackendEvent(event: BackendEvent) {
    if (event.type === 'presence' && event.username) {
      setOnlineUsernames((prev) => {
        const next = new Set(prev)
        if (event.online) next.add(event.username as string)
        else next.delete(event.username as string)
        return next
      })
    } else if (event.type === 'presence_snapshot' && event.online_usernames) {
      setOnlineUsernames(new Set(event.online_usernames))
    } else if (event.type === 'avatar_update') {
      refreshOwnAvatar()
    } else if (event.type === 'group_invite') {
      Api.contacts().then(setContacts)
    }
    refreshSidebar()
    setRefreshSignal((n) => n + 1)
  }

  async function handleChangeProfilePicture(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    const reader = new FileReader()
    reader.onload = async () => {
      const dataUrl = reader.result as string
      const base64 = dataUrl.split(',')[1] ?? ''
      await Api.setProfilePicture(base64, file.type || 'image/png')
      await refreshOwnAvatar()
      await refreshSidebar()
    }
    reader.readAsDataURL(file)
  }

  async function handleNewChat(newUsername: string) {
    const name = newUsername.trim()
    if (!name) return
    await Api.addContact(name)
    setShowNewChat(false)
    await refreshSidebar()
    setActiveTab('dm')
    setSelectedId(name)
  }

  async function handleCreateGroup(name: string, members: string[]) {
    const groupId = await Api.createGroup(name, members)
    setShowGroupCreate(false)
    await refreshSidebar()
    setActiveTab('group')
    setSelectedId(`group:${groupId}`)
  }

  function togglePin(conversationId: string, currentlyPinned: boolean) {
    Api.setPinned(conversationId, !currentlyPinned).then(refreshSidebar)
  }

  const visibleConversations = conversations.filter((c) => c.kind === activeTab)
  const selected = conversations.find((c) => c.conversation_id === selectedId) ?? null
  const selectedGroupId = selected && selected.kind === 'group' ? selected.conversation_id.split(':').slice(1).join(':') : null

  return (
    <div className="flex h-full w-full">
      <div className="flex shrink-0 flex-col items-center gap-1 self-start pt-1">
        <button
          onClick={() => setSidebarVisible((v) => !v)}
          title="Show/hide sidebar"
          className="flex h-9 w-9 items-center justify-center text-text-secondary hover:text-text-primary"
        >
          <Menu size={20} />
        </button>
        <ThemeToggle />
      </div>

      {sidebarVisible && (
        <div className="flex w-64 shrink-0 flex-col border-r border-border bg-sidebar">
          <div className="flex items-center gap-3 p-3">
            <label className="cursor-pointer" title="Click to change your profile picture">
              <Avatar imageUrl={ownAvatar} name={username} size={44} />
              <input type="file" accept="image/*" className="hidden" onChange={handleChangeProfilePicture} />
            </label>
            <span className="truncate font-semibold text-text-primary">{username}</span>
          </div>

          <div className="flex items-center gap-2 px-3 pb-2">
            <button
              onClick={() => setActiveTab('dm')}
              className={`flex-1 rounded-full py-1.5 text-sm font-semibold ${
                activeTab === 'dm' ? 'gradient-accent text-white' : 'text-text-secondary'
              }`}
            >
              Chats
            </button>
            <button
              onClick={() => setActiveTab('group')}
              className={`flex-1 rounded-full py-1.5 text-sm font-semibold ${
                activeTab === 'group' ? 'gradient-accent text-white' : 'text-text-secondary'
              }`}
            >
              Groups
            </button>
            <button
              onClick={() => (activeTab === 'dm' ? setShowNewChat(true) : setShowGroupCreate(true))}
              title={activeTab === 'dm' ? 'New chat' : 'New group'}
              className="gradient-accent flex h-[34px] w-[34px] shrink-0 items-center justify-center rounded-full text-white"
            >
              {activeTab === 'dm' ? <PenSquare size={16} /> : <Users size={16} />}
            </button>
          </div>

          <div className="flex-1 overflow-y-auto">
            {visibleConversations.map((c) => (
              <ConversationRow
                key={c.conversation_id}
                summary={c}
                avatarUrl={rowAvatars[c.conversation_id]}
                online={onlineUsernames.has(c.conversation_id)}
                selected={c.conversation_id === selectedId}
                onSelect={() => setSelectedId(c.conversation_id)}
                onTogglePin={() => togglePin(c.conversation_id, c.pinned)}
              />
            ))}
          </div>
        </div>
      )}

      <div className="min-w-0 flex-1">
        {selected ? (
          <ChatView
            key={selected.conversation_id}
            conversationId={selected.conversation_id}
            displayName={selected.display_name}
            isGroup={selected.kind === 'group'}
            online={onlineUsernames.has(selected.conversation_id)}
            avatarUrl={selected.kind === 'dm' ? rowAvatars[selected.conversation_id] : undefined}
            refreshSignal={refreshSignal}
            onOpenGroupInfo={() => setShowGroupInfo(true)}
            onSidebarRefresh={refreshSidebar}
          />
        ) : (
          <div className="flex h-full items-center justify-center bg-chat-area text-text-secondary">
            Select a conversation
          </div>
        )}
      </div>

      {showNewChat && <NewChatPrompt onCancel={() => setShowNewChat(false)} onSubmit={handleNewChat} />}
      {showGroupCreate && (
        <GroupCreateDialog contacts={contacts} onCancel={() => setShowGroupCreate(false)} onCreate={handleCreateGroup} />
      )}
      {showGroupInfo && selected && selectedGroupId && (
        <GroupInfoDialog
          groupId={selectedGroupId}
          groupName={selected.display_name}
          onClose={() => setShowGroupInfo(false)}
          onChanged={() => {
            refreshSidebar()
            setRefreshSignal((n) => n + 1)
          }}
        />
      )}
    </div>
  )
}

function NewChatPrompt({ onCancel, onSubmit }: { onCancel: () => void; onSubmit: (username: string) => void }) {
  const [value, setValue] = useState('')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
      <div className="w-80 rounded-2xl bg-sidebar p-6 shadow-xl">
        <h2 className="mb-4 text-lg font-bold text-text-primary">New Chat</h2>
        <input
          autoFocus
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && onSubmit(value)}
          placeholder="Username"
          className="mb-4 w-full rounded-xl border border-border bg-input px-3 py-2 text-text-primary outline-none focus:border-accent"
        />
        <div className="flex justify-end gap-2">
          <button
            onClick={onCancel}
            className="rounded-full border border-border px-4 py-2 text-sm font-semibold text-text-secondary hover:bg-hover-row"
          >
            Cancel
          </button>
          <button
            onClick={() => onSubmit(value)}
            className="gradient-accent rounded-full px-4 py-2 text-sm font-semibold text-white"
          >
            Start chat
          </button>
        </div>
      </div>
    </div>
  )
}
