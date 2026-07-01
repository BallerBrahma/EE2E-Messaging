import { useState, type ReactNode } from 'react'
import { Api } from '../api'

interface RecoveryFlowProps {
  server: string
  initialUsername: string
  onCancel: () => void
  onRecovered: (username: string) => void
}

const inputClasses =
  'w-full rounded-2xl border border-border bg-input px-4 py-2 text-text-primary outline-none focus:border-accent'

export default function RecoveryFlow({ server, initialUsername, onCancel, onRecovered }: RecoveryFlowProps) {
  const [username, setUsername] = useState(initialUsername)
  const [phrase, setPhrase] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [status, setStatus] = useState('')
  const [busy, setBusy] = useState(false)

  async function handleRecover() {
    const name = username.trim()
    const cleanPhrase = phrase.trim().toLowerCase()
    if (!name || !cleanPhrase || !newPassword) {
      setStatus('all fields are required')
      return
    }
    if (newPassword !== confirmPassword) {
      setStatus('passwords do not match')
      return
    }
    setBusy(true)
    setStatus('')
    try {
      const result = await Api.recoverAccount(server, name, cleanPhrase, newPassword)
      onRecovered(result.username)
    } catch (err) {
      setStatus(`recovery failed: ${err}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-bold text-text-primary">Recover your account</h2>
        <p className="mt-1 text-sm text-text-secondary">
          Enter your username, your 12-word recovery phrase, and a new password.
        </p>
      </div>
      <Field label="Username">
        <input className={inputClasses} value={username} onChange={(e) => setUsername(e.target.value)} />
      </Field>
      <Field label="Recovery phrase (12 words)">
        <textarea
          className={`${inputClasses} resize-none`}
          rows={2}
          value={phrase}
          onChange={(e) => setPhrase(e.target.value)}
        />
      </Field>
      <Field label="New password">
        <input
          className={inputClasses}
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
        />
      </Field>
      <Field label="Confirm new password">
        <input
          className={inputClasses}
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
        />
      </Field>
      {status && <p className="text-sm text-danger">{status}</p>}
      <div className="flex gap-3 pt-2">
        <button
          onClick={onCancel}
          className="flex-1 rounded-full border border-border px-4 py-2 font-semibold text-text-secondary transition-colors hover:bg-hover-row"
        >
          Cancel
        </button>
        <button
          disabled={busy}
          onClick={handleRecover}
          className="gradient-accent flex-1 rounded-full px-4 py-2 font-semibold text-white disabled:opacity-50"
        >
          Recover account
        </button>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-text-secondary">{label}</span>
      {children}
    </label>
  )
}
