// Local, offline spelling checker + autocorrect for the message input --
// TypeScript port of client/spellcheck.py.
//
// Deliberately local-only: this app's entire point is that message content
// never reaches a third party unencrypted, so spell-check suggestions must
// never be fetched from a network API. `nspell` is a pure-JS, offline
// Hunspell-compatible checker -- no network calls, bundled at build time.
//
// The dictionary data (`dictionaries/en.aff`/`en.dic`) is vendored from the
// `dictionary-en` npm package (MIT/BSD, see dictionaries/LICENSE) rather
// than imported from the package directly: its own loader uses Node's `fs`
// + top-level `await` to lazily read sibling files, which doesn't bundle
// for a browser target (verified -- `vite build` fails on it). Importing
// the raw .aff/.dic text via Vite's `?raw` loader sidesteps that entirely.
//
// Mirrors client/spellcheck.py's behavior exactly, including the same
// curated contraction/typo map (checked before falling back to the
// dictionary's own best-guess correction).

import nspell from 'nspell'
import aff from './dictionaries/en.aff?raw'
import dic from './dictionaries/en.dic?raw'

const checker = nspell(aff, dic)

// Curated, unambiguous corrections (mostly missing-apostrophe contractions) --
// applied automatically as you type, the way a phone keyboard's autocorrect
// would. Deliberately excludes words that are ambiguous with a common valid
// word (e.g. "its"/"it's", "well", "were", "id", "ill") to avoid "correcting"
// something that was already right. Same map as client/spellcheck.py.
const AUTOCORRECT_MAP: Record<string, string> = {
  dont: "don't", cant: "can't", wont: "won't", isnt: "isn't",
  arent: "aren't", wasnt: "wasn't", werent: "weren't", hasnt: "hasn't",
  havent: "haven't", hadnt: "hadn't", doesnt: "doesn't", didnt: "didn't",
  shouldnt: "shouldn't", wouldnt: "wouldn't", couldnt: "couldn't",
  mustnt: "mustn't", neednt: "needn't", aint: "ain't",
  im: "I'm", ive: "I've", youre: "you're", youve: "you've", youll: "you'll",
  theyre: "they're", theyve: "they've", theyll: "they'll",
  whats: "what's", wheres: "where's", whos: "who's", hows: "how's",
  thats: "that's", theres: "there's", shes: "she's",
  teh: 'the', recieve: 'receive', seperate: 'separate',
  definately: 'definitely', occured: 'occurred', untill: 'until',
}

export function isMisspelled(word: string): boolean {
  return word.length > 1 && !checker.correct(word.toLowerCase())
}

export function suggestions(word: string): string[] {
  const candidates = checker.suggest(word.toLowerCase())
  return [...candidates].sort().slice(0, 5)
}

function matchCase(original: string, corrected: string): string {
  if (original[0] && original[0] === original[0].toUpperCase() && original[0] !== original[0].toLowerCase()) {
    return corrected.slice(0, 1).toUpperCase() + corrected.slice(1)
  }
  return corrected
}

/** Returns a corrected form of `word` if one is known, else null. Checks the
 * curated contraction/typo map first, then falls back to the dictionary's
 * own best-guess correction for otherwise-misspelled words. */
export function autocorrectWord(word: string): string | null {
  const lower = word.toLowerCase()
  if (lower in AUTOCORRECT_MAP) {
    return matchCase(word, AUTOCORRECT_MAP[lower])
  }
  if (isMisspelled(word)) {
    const guess = checker.suggest(lower)[0]
    if (guess && guess !== lower) {
      return matchCase(word, guess)
    }
  }
  return null
}
