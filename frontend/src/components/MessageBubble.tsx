import { useState, type MouseEvent } from 'react'
import { Paperclip } from 'lucide-react'
import Avatar from './Avatar'
import type { StoredMessage } from '../api'

interface MessageBubbleProps {
  message: StoredMessage
  isOwn: boolean
  avatarUrl?: string | null
  onDelete: (messageId: string) => void
}

function formatTimestamp(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function downloadAttachment(filename: string, mime: string, dataB64: string) {
  const byteChars = atob(dataB64)
  const bytes = new Uint8Array(byteChars.length)
  for (let i = 0; i < byteChars.length; i++) bytes[i] = byteChars.charCodeAt(i)
  const blob = new Blob([bytes], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export default function MessageBubble({ message, isOwn, avatarUrl, onDelete }: MessageBubbleProps) {
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null)

  if (message.kind === 'system') {
    return (
      <div className="flex justify-center px-2 py-1">
        <span className="text-xs text-text-system">{message.body.content}</span>
      </div>
    )
  }

  function handleContextMenu(e: MouseEvent) {
    if (!isOwn) return
    e.preventDefault()
    setMenu({ x: e.clientX, y: e.clientY })
  }

  const bubbleClasses = isOwn
    ? 'max-w-[340px] rounded-2xl border border-transparent bg-sent-bubble px-3 py-2 text-white'
    : 'max-w-[340px] rounded-2xl border border-border bg-received-bubble px-3 py-2 text-text-primary'

  return (
    <div className={`flex items-end gap-1.5 px-2 py-0.5 ${isOwn ? 'justify-end' : 'justify-start'}`}>
      {!isOwn && <Avatar imageUrl={avatarUrl} name={message.sender_username ?? '?'} size={24} className="mb-1" />}
      <div className={`flex max-w-[70%] flex-col ${isOwn ? 'items-end' : 'items-start'}`}>
        <div
          className={bubbleClasses}
          onContextMenu={handleContextMenu}
          title={!isOwn ? (message.sender_username ?? undefined) : undefined}
        >
          {message.kind === 'attachment' ? (
            <div className="flex items-center gap-2">
              <Paperclip size={14} className="shrink-0" />
              <span className="break-all">
                {message.body.filename} ({Math.max(1, Math.round((message.body.size ?? 0) / 1024))} KB)
              </span>
              <button
                onClick={() => downloadAttachment(message.body.filename, message.body.mime, message.body.data_b64)}
                className="shrink-0 rounded-full border border-current px-2 py-0.5 text-xs"
              >
                Save
              </button>
            </div>
          ) : (
            <span className="whitespace-pre-wrap break-words">{message.body.content}</span>
          )}
        </div>
        <span className="mt-0.5 text-[11px] text-text-system">{formatTimestamp(message.timestamp)}</span>
      </div>

      {menu && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setMenu(null)} />
          <div
            className="fixed z-50 rounded-lg border border-border bg-sidebar p-1 shadow-lg"
            style={{ left: menu.x, top: menu.y }}
          >
            <button
              className="whitespace-nowrap rounded px-3 py-1 text-left text-sm text-danger hover:bg-hover-row"
              onClick={() => {
                setMenu(null)
                onDelete(message.message_id)
              }}
            >
              Delete for Everyone
            </button>
          </div>
        </>
      )}
    </div>
  )
}
