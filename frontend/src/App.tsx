import { useEffect, useState } from 'react'
import { onPywebviewReady } from './api'
import LoginScreen from './components/LoginScreen'
import MainWindow from './components/MainWindow'

export default function App() {
  const [ready, setReady] = useState(false)
  const [username, setUsername] = useState<string | null>(null)

  useEffect(() => {
    onPywebviewReady(() => setReady(true))
  }, [])

  if (!ready) {
    return <div className="flex h-full w-full items-center justify-center bg-app-bg text-text-secondary">Loading...</div>
  }

  if (!username) {
    return <LoginScreen onLoggedIn={setUsername} />
  }

  return <MainWindow username={username} />
}
