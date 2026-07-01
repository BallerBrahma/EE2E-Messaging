import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import { Api } from '../api'

interface GroupInfoDialogProps {
  groupId: string
  groupName: string
  onClose: () => void
  onChanged: () => void
}

export default function GroupInfoDialog({ groupId, groupName, onClose, onChanged }: GroupInfoDialogProps) {
  const [members, setMembers] = useState<string[]>([])
  const [newMember, setNewMember] = useState('')
  const [error, setError] = useState('')

  async function refresh() {
    setMembers(await Api.groupMembers(groupId))
  }

  useEffect(() => {
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupId])

  async function handleRemove(username: string) {
    setError('')
    try {
      await Api.removeGroupMember(groupId, username)
      await refresh()
      onChanged()
    } catch (err) {
      setError(String(err))
    }
  }

  async function handleAdd() {
    const username = newMember.trim()
    if (!username) return
    setError('')
    try {
      await Api.addGroupMember(groupId, username)
      setNewMember('')
      await refresh()
      onChanged()
    } catch (err) {
      setError(String(err))
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
      <div className="w-80 rounded-2xl bg-sidebar p-6 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-bold text-text-primary">{groupName}</h2>
          <button onClick={onClose} className="text-text-secondary hover:text-text-primary">
            <X size={18} />
          </button>
        </div>
        {error && <p className="mb-2 text-sm text-danger">{error}</p>}
        <div className="mb-4 max-h-48 space-y-1 overflow-y-auto">
          {members.map((m) => (
            <div key={m} className="flex items-center justify-between rounded px-2 py-1 hover:bg-hover-row">
              <span className="text-sm text-text-primary">{m}</span>
              <button onClick={() => handleRemove(m)} className="text-xs font-semibold text-danger">
                Remove
              </button>
            </div>
          ))}
        </div>
        <div className="flex gap-2">
          <input
            value={newMember}
            onChange={(e) => setNewMember(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
            placeholder="username to add"
            className="flex-1 rounded-xl border border-border bg-input px-3 py-2 text-sm text-text-primary outline-none focus:border-accent"
          />
          <button onClick={handleAdd} className="gradient-accent rounded-full px-4 py-2 text-sm font-semibold text-white">
            Add
          </button>
        </div>
      </div>
    </div>
  )
}
