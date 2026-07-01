import { Pin } from 'lucide-react'
import Avatar from './Avatar'
import type { ConversationSummary } from '../api'

interface ConversationRowProps {
  summary: ConversationSummary
  avatarUrl?: string | null
  online?: boolean
  selected: boolean
  onSelect: () => void
  onTogglePin: () => void
}

function formatTimestamp(timestamp: number): string {
  if (!timestamp) return ''
  const date = new Date(timestamp * 1000)
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

export default function ConversationRow({ summary, avatarUrl, online, selected, onSelect, onTogglePin }: ConversationRowProps) {
  function handleContextMenu(e: React.MouseEvent) {
    e.preventDefault()
    onTogglePin()
  }

  return (
    <div
      onClick={onSelect}
      onContextMenu={handleContextMenu}
      title="Right-click to pin/unpin"
      className={`flex cursor-pointer items-center gap-3 border-b border-border px-3 py-2 ${
        selected ? 'bg-selected-row' : 'hover:bg-hover-row'
      }`}
    >
      <Avatar imageUrl={avatarUrl} name={summary.display_name} size={40} online={summary.kind === 'dm' ? online : undefined} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1">
          {summary.pinned && <Pin size={12} className="shrink-0 text-text-secondary" />}
          <span className="truncate font-semibold text-text-primary">{summary.display_name}</span>
        </div>
        <div className="truncate text-xs text-text-secondary">{summary.last_preview}</div>
      </div>
      <div className="shrink-0 text-xs text-text-system">{formatTimestamp(summary.last_timestamp)}</div>
    </div>
  )
}
