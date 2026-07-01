import { useState } from 'react'

interface RecoveryPhraseModalProps {
  phrase: string
  onContinue: () => void
}

export default function RecoveryPhraseModal({ phrase, onContinue }: RecoveryPhraseModalProps) {
  const [acknowledged, setAcknowledged] = useState(false)
  const words = phrase.trim().split(/\s+/)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-[440px] rounded-2xl bg-sidebar p-8 shadow-xl">
        <h2 className="mb-2 text-xl font-bold text-text-primary">Save your recovery phrase</h2>
        <p className="mb-4 text-sm text-text-secondary">
          Write these 12 words down somewhere safe (a password manager, or on paper). They're the
          only way to get back into your account if you forget your password -- we can't recover
          it for you otherwise.
        </p>
        <div className="mb-5 grid grid-cols-3 gap-2 rounded-xl border border-border bg-input p-4">
          {words.map((word, i) => (
            <div key={i} className="flex items-baseline gap-1.5 text-sm">
              <span className="w-4 text-right text-text-system">{i + 1}.</span>
              <span className="font-mono font-semibold text-text-primary">{word}</span>
            </div>
          ))}
        </div>
        <label className="mb-4 flex items-center gap-2 text-sm text-text-secondary">
          <input type="checkbox" checked={acknowledged} onChange={(e) => setAcknowledged(e.target.checked)} />
          I've saved this somewhere safe
        </label>
        <button
          disabled={!acknowledged}
          onClick={onContinue}
          className="gradient-accent w-full rounded-full px-4 py-2 font-semibold text-white disabled:opacity-50"
        >
          Continue
        </button>
      </div>
    </div>
  )
}
