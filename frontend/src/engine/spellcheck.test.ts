import { describe, expect, it } from 'vitest'
import { autocorrectWord, isMisspelled, suggestions } from './spellcheck'

describe('spellcheck', () => {
  it('flags misspelled words and accepts correct ones', () => {
    expect(isMisspelled('helllo')).toBe(true)
    expect(isMisspelled('hello')).toBe(false)
  })

  it('suggests candidates for a misspelled word', () => {
    expect(suggestions('helllo')).toContain('hello')
  })

  it('autocorrects curated contractions regardless of dictionary validity', () => {
    expect(autocorrectWord('whats')).toBe("what's")
    expect(autocorrectWord('dont')).toBe("don't")
    expect(autocorrectWord('Im')).toBe("I'm")
  })

  it('falls back to the dictionary correction for other typos', () => {
    expect(autocorrectWord('helllo')).toBe('hello')
  })

  it('returns null for already-correct words', () => {
    expect(autocorrectWord('hello')).toBeNull()
  })
})
