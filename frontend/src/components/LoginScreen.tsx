import { useEffect, useState, type ReactNode } from 'react'
import { Fingerprint } from 'lucide-react'
import { Api } from '../api'
import RecoveryFlow from './RecoveryFlow'
import RecoveryPhraseModal from './RecoveryPhraseModal'
import ThemeToggle from './ThemeToggle'

interface LoginScreenProps {
  onLoggedIn: (username: string) => void
}

const inputClasses =
  'w-full rounded-2xl border border-border bg-input px-4 py-2 text-text-primary outline-none focus:border-accent'

const DEFAULT_SERVER_URL = import.meta.env.VITE_DEFAULT_SERVER_URL ?? 'ws://localhost:8765'

export default function LoginScreen({ onLoggedIn }: LoginScreenProps) {
  const [server, setServer] = useState(DEFAULT_SERVER_URL)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [status, setStatus] = useState('')
  const [busy, setBusy] = useState(false)

  const [biometricSupported, setBiometricSupported] = useState(false)
  const [rememberedUsername, setRememberedUsername] = useState<string | null>(null)
  const [showManualForm, setShowManualForm] = useState(false)
  const [rememberMe, setRememberMe] = useState(false)

  const [pendingRecoveryPhrase, setPendingRecoveryPhrase] = useState<string | null>(null)
  const [pendingUsername, setPendingUsername] = useState('')
  const [showRecoveryFlow, setShowRecoveryFlow] = useState(false)

  useEffect(() => {
    Api.hasBiometricSupport().then(setBiometricSupported)
    Api.getRememberedUsername().then(setRememberedUsername)
  }, [])

  async function afterSuccessfulAuth(name: string) {
    if (biometricSupported && rememberMe) {
      try {
        await Api.rememberCredentials(name, password)
      } catch {
        // non-fatal -- login already succeeded, just couldn't save to Keychain
      }
    }
    onLoggedIn(name)
  }

  async function handleRegister() {
    const name = username.trim()
    if (!name || !password) {
      setStatus('username and password are required')
      return
    }
    setBusy(true)
    setStatus('')
    try {
      if (await Api.hasLocalIdentity(name)) {
        setStatus('a local identity for this username already exists -- use Log in')
        return
      }
      const result = await Api.register(server, name, password)
      setPendingUsername(name)
      setPendingRecoveryPhrase(result.recovery_phrase)
    } catch (err) {
      setStatus(`registration failed: ${err}`)
    } finally {
      setBusy(false)
    }
  }

  async function handleRecoveryPhraseAcknowledged() {
    const name = pendingUsername
    setPendingRecoveryPhrase(null)
    await afterSuccessfulAuth(name)
  }

  async function handleLogin() {
    const name = username.trim()
    if (!name || !password) {
      setStatus('username and password are required')
      return
    }
    setBusy(true)
    setStatus('')
    try {
      if (!(await Api.hasLocalIdentity(name))) {
        setStatus('no local identity for this username -- use Create account')
        return
      }
      await Api.login(server, name, password)
      await afterSuccessfulAuth(name)
    } catch (err) {
      setStatus(`login failed: ${err}`)
    } finally {
      setBusy(false)
    }
  }

  async function handleBiometricLogin() {
    setBusy(true)
    setStatus('')
    try {
      const result = await Api.loginWithBiometrics(server)
      onLoggedIn(result.username)
    } catch (err) {
      setStatus(`Touch ID login failed: ${err}`)
    } finally {
      setBusy(false)
    }
  }

  async function handleNotYou() {
    await Api.forgetRememberedLogin()
    setRememberedUsername(null)
    setShowManualForm(true)
  }

  const showBiometricPrompt = biometricSupported && rememberedUsername && !showManualForm

  return (
    <div className="flex h-full w-full items-center justify-center bg-app-bg">
      {pendingRecoveryPhrase && (
        <RecoveryPhraseModal phrase={pendingRecoveryPhrase} onContinue={handleRecoveryPhraseAcknowledged} />
      )}
      <div className="w-96 rounded-2xl bg-sidebar p-8 shadow-sm">
        <div className="mb-6 flex items-center justify-between">
          <h1 className="text-2xl font-bold text-text-primary">Messages</h1>
          <ThemeToggle />
        </div>

        {showRecoveryFlow ? (
          <RecoveryFlow
            server={server}
            initialUsername={username}
            onCancel={() => setShowRecoveryFlow(false)}
            onRecovered={(name) => onLoggedIn(name)}
          />
        ) : showBiometricPrompt ? (
          <div className="space-y-4">
            <button
              disabled={busy}
              onClick={handleBiometricLogin}
              className="gradient-accent flex w-full items-center justify-center gap-2 rounded-full px-4 py-3 font-semibold text-white disabled:opacity-50"
            >
              <Fingerprint size={18} />
              Log in as {rememberedUsername} with Touch ID
            </button>
            {status && <p className="text-sm text-danger">{status}</p>}
            <button
              onClick={handleNotYou}
              className="w-full text-center text-sm text-text-secondary hover:text-text-primary"
            >
              Not you? Log in differently
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <Field label="Server">
              <input className={inputClasses} value={server} onChange={(e) => setServer(e.target.value)} />
            </Field>
            <Field label="Username">
              <input className={inputClasses} value={username} onChange={(e) => setUsername(e.target.value)} />
            </Field>
            <Field label="Password">
              <input
                className={inputClasses}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
              />
            </Field>
            {biometricSupported && (
              <label className="flex items-center gap-2 text-sm text-text-secondary">
                <input type="checkbox" checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} />
                Remember me with Touch ID
              </label>
            )}
            {status && <p className="text-sm text-danger">{status}</p>}
            <div className="flex gap-3 pt-2">
              <button
                disabled={busy}
                onClick={handleRegister}
                className="flex-1 rounded-full border border-border px-4 py-2 font-semibold text-text-secondary transition-colors hover:bg-hover-row disabled:opacity-50"
              >
                Create account
              </button>
              <button
                disabled={busy}
                onClick={handleLogin}
                className="gradient-accent flex-1 rounded-full px-4 py-2 font-semibold text-white disabled:opacity-50"
              >
                Log in
              </button>
            </div>
            <button
              onClick={() => setShowRecoveryFlow(true)}
              className="w-full text-center text-sm text-text-secondary hover:text-text-primary"
            >
              Forgot password?
            </button>
          </div>
        )}
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
