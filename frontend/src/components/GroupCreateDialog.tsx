import { useState } from 'react'

interface GroupCreateDialogProps {
  contacts: string[]
  onCancel: () => void
  onCreate: (name: string, members: string[]) => void
}

export default function GroupCreateDialog({ contacts, onCancel, onCreate }: GroupCreateDialogProps) {
  const [name, setName] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [extra, setExtra] = useState('')

  function toggle(contact: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(contact)) next.delete(contact)
      else next.add(contact)
      return next
    })
  }

  function handleCreate() {
    const members = new Set(selected)
    extra
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((m) => members.add(m))
    if (!name.trim() || members.size === 0) return
    onCreate(name.trim(), Array.from(members))
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
      <div className="w-96 rounded-2xl bg-sidebar p-6 shadow-xl">
        <h2 className="mb-4 text-lg font-bold text-text-primary">New Group</h2>
        <label className="mb-3 block">
          <span className="mb-1 block text-xs font-medium text-text-secondary">Group name</span>
          <input
            className="w-full rounded-xl border border-border bg-input px-3 py-2 text-text-primary outline-none focus:border-accent"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        {contacts.length > 0 && (
          <div className="mb-3">
            <span className="mb-1 block text-xs font-medium text-text-secondary">Include contacts</span>
            <div className="max-h-32 space-y-1 overflow-y-auto">
              {contacts.map((c) => (
                <label key={c} className="flex items-center gap-2 text-sm text-text-primary">
                  <input type="checkbox" checked={selected.has(c)} onChange={() => toggle(c)} />
                  {c}
                </label>
              ))}
            </div>
          </div>
        )}
        <label className="mb-4 block">
          <span className="mb-1 block text-xs font-medium text-text-secondary">Other members (comma-separated)</span>
          <input
            className="w-full rounded-xl border border-border bg-input px-3 py-2 text-text-primary outline-none focus:border-accent"
            value={extra}
            onChange={(e) => setExtra(e.target.value)}
          />
        </label>
        <div className="flex justify-end gap-2">
          <button
            onClick={onCancel}
            className="rounded-full border border-border px-4 py-2 text-sm font-semibold text-text-secondary hover:bg-hover-row"
          >
            Cancel
          </button>
          <button onClick={handleCreate} className="gradient-accent rounded-full px-4 py-2 text-sm font-semibold text-white">
            Create
          </button>
        </div>
      </div>
    </div>
  )
}
