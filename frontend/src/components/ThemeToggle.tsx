import { Moon, Sun } from 'lucide-react'
import { useTheme } from '../theme'

export default function ThemeToggle({ className = '' }: { className?: string }) {
  const { theme, toggleTheme } = useTheme()
  return (
    <button
      onClick={toggleTheme}
      title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
      className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-text-secondary hover:bg-hover-row ${className}`}
    >
      {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  )
}
