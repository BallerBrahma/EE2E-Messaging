import { useCallback, useEffect, useRef, useState } from 'react'
import { Info } from 'lucide-react'
import Avatar from './Avatar'
import MessageBubble from './MessageBubble'
import MessageInput from './MessageInput'
import { Api, type StoredMessage } from '../api'

interface ChatViewProps {
  conversationId: string
  displayName: string
  isGroup: boolean
  online?: boolean
  avatarUrl?: string | null
  refreshSignal: number
  onOpenGroupInfo: () => void
  onSidebarRefresh: () => void
}

export default function ChatView({
  conversationId,
  displayName,
  isGroup,
  online,
  avatarUrl,
  refreshSignal,
  onOpenGroupInfo,
  onSidebarRefresh,
}: ChatViewProps) {
  const [messages, setMessages] = useState<StoredMessage[]>([])
  const [memberCount, setMemberCount] = useState<number | null>(null)
  const [senderAvatars, setSenderAvatars] = useState<Record<string, string | null>>({})
  const scrollRef = useRef<HTMLDivElement>(null)

  const loadHistory = useCallback(async () => {
    const history = await Api.getHistory(conversationId)
    setMessages(history)

    if (isGroup) {
      const groupId = conversationId.split(':').slice(1).join(':')
      const members = await Api.groupMembers(groupId)
      setMemberCount(members.length)
    }

    const senders = Array.from(
      new Set(history.filter((m) => m.direction === 'received' && m.sender_username).map((m) => m.sender_username as string)),
    )
    const avatarEntries = await Promise.all(senders.map(async (s) => [s, await Api.getAvatar(s)] as const))
    setSenderAvatars(Object.fromEntries(avatarEntries))
  }, [conversationId, isGroup])

  useEffect(() => {
    loadHistory()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadHistory, refreshSignal])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight })
  }, [messages])

  async function handleSend(text: string) {
    await Api.sendText(conversationId, text)
    await loadHistory()
    onSidebarRefresh()
  }

  function handleAttach(file: File) {
    const reader = new FileReader()
    reader.onload = async () => {
      const dataUrl = reader.result as string
      const base64 = dataUrl.split(',')[1] ?? ''
      await Api.sendAttachment(conversationId, file.name, file.type || 'application/octet-stream', base64)
      await loadHistory()
      onSidebarRefresh()
    }
    reader.readAsDataURL(file)
  }

  async function handleDelete(messageId: string) {
    await Api.deleteMessage(conversationId, messageId)
    await loadHistory()
    onSidebarRefresh()
  }

  const subtitle = isGroup ? `${memberCount ?? '...'} Members` : online ? 'Online' : 'Offline'

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-border bg-sidebar px-4 py-3">
        <Avatar imageUrl={avatarUrl} name={displayName} size={36} online={isGroup ? undefined : online} />
        <div className="min-w-0 flex-1">
          <div className="truncate font-semibold text-text-primary">{displayName}</div>
          <div className="truncate text-xs text-text-secondary">{subtitle}</div>
        </div>
        {isGroup && (
          <button
            onClick={onOpenGroupInfo}
            title="Group info"
            className="rounded-full p-1.5 text-text-secondary hover:bg-hover-row"
          >
            <Info size={18} />
          </button>
        )}
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto bg-chat-area py-3">
        {messages.map((msg) => (
          <MessageBubble
            key={msg.message_id}
            message={msg}
            isOwn={msg.direction === 'sent'}
            avatarUrl={msg.sender_username ? senderAvatars[msg.sender_username] : undefined}
            onDelete={handleDelete}
          />
        ))}
      </div>

      <MessageInput onSend={handleSend} onAttach={handleAttach} />
    </div>
  )
}
