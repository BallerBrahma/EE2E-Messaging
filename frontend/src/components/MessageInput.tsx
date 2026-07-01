import { useRef, useState, type ChangeEvent, type KeyboardEvent } from 'react'
import { Plus, Send } from 'lucide-react'
import { Api } from '../api'

interface MessageInputProps {
  onSend: (text: string) => void
  onAttach: (file: File) => void
}

const BOUNDARY_CHARS = new Set([' ', '\t', '\n', ',', '.', '!', '?', ';', ':'])
const WORD_RE = /[A-Za-z']+/g

function wordEndingAt(text: string, endPos: number): [string, number, number] | null {
  WORD_RE.lastIndex = 0
  let match: RegExpExecArray | null
  while ((match = WORD_RE.exec(text)) !== null) {
    if (match.index + match[0].length === endPos) {
      return [match[0], match.index, match.index + match[0].length]
    }
  }
  return null
}

/** iOS-keyboard-style autocorrect: finishing a word (space/punctuation/Enter)
 * auto-fixes it via the same curated contraction/typo logic that ran locally
 * in the old Qt client (client/spellcheck.py), now reached over the bridge. */
async function autocorrectBeforeCursor(
  fullText: string,
  cursorPos: number,
  boundaryLen: number,
): Promise<{ text: string; cursor: number } | null> {
  const endPos = cursorPos - boundaryLen
  if (endPos <= 0) return null
  const hit = wordEndingAt(fullText, endPos)
  if (!hit) return null
  const [word, start, end] = hit
  const corrected = await Api.autocorrectWord(word)
  if (!corrected || corrected === word) return null
  const newText = fullText.slice(0, start) + corrected + fullText.slice(end)
  return { text: newText, cursor: cursorPos + (corrected.length - word.length) }
}

export default function MessageInput({ onSend, onAttach }: MessageInputProps) {
  const [text, setText] = useState('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  function submit(value: string) {
    const trimmed = value.trim()
    if (!trimmed) return
    onSend(trimmed)
    setText('')
  }

  async function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key !== 'Enter' || e.shiftKey) return
    e.preventDefault()
    const el = textareaRef.current
    if (el) {
      const result = await autocorrectBeforeCursor(text, el.selectionStart, 0)
      if (result) {
        submit(result.text)
        return
      }
    }
    submit(text)
  }

  function handleChange(e: ChangeEvent<HTMLTextAreaElement>) {
    const newValue = e.target.value
    const cursorPos = e.target.selectionStart
    setText(newValue)

    const lastChar = newValue[cursorPos - 1]
    if (!lastChar || !BOUNDARY_CHARS.has(lastChar)) return
    autocorrectBeforeCursor(newValue, cursorPos, 1).then((result) => {
      if (!result) return
      // Only apply if nothing changed while the bridge call was in flight.
      if (textareaRef.current && textareaRef.current.value === newValue) {
        setText(result.text)
        requestAnimationFrame(() => {
          textareaRef.current?.setSelectionRange(result.cursor, result.cursor)
        })
      }
    })
  }

  function handleAttachClick() {
    fileInputRef.current?.click()
  }

  function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) onAttach(file)
    e.target.value = ''
  }

  return (
    <div className="flex items-end gap-2 border-t border-border bg-sidebar px-3 py-2">
      <button
        onClick={handleAttachClick}
        title="Send an attachment"
        className="gradient-accent flex h-[34px] w-[34px] shrink-0 items-center justify-center rounded-full text-white"
      >
        <Plus size={18} strokeWidth={3} />
      </button>
      <input ref={fileInputRef} type="file" className="hidden" onChange={handleFileChange} />
      <textarea
        ref={textareaRef}
        value={text}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        spellCheck
        rows={1}
        placeholder="Message"
        className="max-h-32 flex-1 resize-none rounded-2xl border border-border bg-input px-4 py-2 text-text-primary outline-none focus:border-accent"
      />
      <button
        onClick={() => submit(text)}
        className="gradient-accent flex shrink-0 items-center gap-1.5 rounded-full px-4 py-2 font-semibold text-white"
      >
        <Send size={14} />
        Send
      </button>
    </div>
  )
}
