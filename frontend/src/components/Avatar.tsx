const PLACEHOLDER_COLORS = [
  '#FF9500', '#FF3B30', '#34C759', '#007AFF', '#5856D6',
  '#AF52DE', '#FF2D55', '#5AC8FA', '#FFCC00', '#8E8E93',
]

function hashColor(name: string): string {
  let hash = 0
  for (let i = 0; i < name.length; i++) {
    hash = (hash * 31 + name.charCodeAt(i)) | 0
  }
  return PLACEHOLDER_COLORS[Math.abs(hash) % PLACEHOLDER_COLORS.length]
}

interface AvatarProps {
  imageUrl?: string | null
  name: string
  size?: number
  /** true/false draws a status dot (green/gray); omit for groups (no single online status). */
  online?: boolean
  className?: string
}

export default function Avatar({ imageUrl, name, size = 40, online, className = '' }: AvatarProps) {
  const initial = (name.trim()[0] || '?').toUpperCase()
  const dotSize = Math.max(8, Math.round(size * 0.28))

  return (
    <div className={`relative shrink-0 ${className}`} style={{ width: size, height: size }}>
      {imageUrl ? (
        <img src={imageUrl} alt={name} className="h-full w-full rounded-full object-cover" />
      ) : (
        <div
          className="flex h-full w-full items-center justify-center rounded-full font-bold text-white"
          style={{ backgroundColor: hashColor(name || '?'), fontSize: size * 0.45 }}
        >
          {initial}
        </div>
      )}
      {online !== undefined && (
        <span
          className="absolute rounded-full border-2 border-sidebar"
          style={{
            width: dotSize,
            height: dotSize,
            right: -1,
            bottom: -1,
            backgroundColor: online ? 'var(--color-online)' : 'var(--color-offline)',
          }}
        />
      )}
    </div>
  )
}
