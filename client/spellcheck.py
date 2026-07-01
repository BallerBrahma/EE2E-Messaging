"""Local, offline spelling checker + autocorrect for the message input.

Deliberately local-only: this app's entire point is that message content
never reaches a third party unencrypted, so spell-check suggestions must
never be fetched from a network API. `pyspellchecker` is a pure-Python,
offline word-frequency dictionary -- no network calls, no external process.

Framework-agnostic (no GUI toolkit dependency) -- called from the
`client/api.py` bridge and exposed to the web frontend. The frontend's
`contentEditable` input relies on the browser/OS's own native spellcheck
for the squiggly-underline visual; this module supplies the custom
autocorrect-as-you-type and right-click suggestion behavior on top of that,
since the OS dictionary doesn't know about our curated contraction map.
"""
from __future__ import annotations

import re

from spellchecker import SpellChecker

_WORD_RE = re.compile(r"[A-Za-z']+")
_checker = SpellChecker()

# Curated, unambiguous corrections (mostly missing-apostrophe contractions) --
# applied automatically as you type, the way a phone keyboard's autocorrect
# would. Deliberately excludes words that are ambiguous with a common valid
# word (e.g. "its"/"it's", "well", "were", "id", "ill") to avoid "correcting"
# something that was already right.
AUTOCORRECT_MAP = {
    "dont": "don't", "cant": "can't", "wont": "won't", "isnt": "isn't",
    "arent": "aren't", "wasnt": "wasn't", "werent": "weren't", "hasnt": "hasn't",
    "havent": "haven't", "hadnt": "hadn't", "doesnt": "doesn't", "didnt": "didn't",
    "shouldnt": "shouldn't", "wouldnt": "wouldn't", "couldnt": "couldn't",
    "mustnt": "mustn't", "neednt": "needn't", "aint": "ain't",
    "im": "I'm", "ive": "I've", "youre": "you're", "youve": "you've", "youll": "you'll",
    "theyre": "they're", "theyve": "they've", "theyll": "they'll",
    "whats": "what's", "wheres": "where's", "whos": "who's", "hows": "how's",
    "thats": "that's", "theres": "there's", "shes": "she's",
    "teh": "the", "recieve": "receive", "seperate": "separate",
    "definately": "definitely", "occured": "occurred", "untill": "until",
}


def is_misspelled(word: str) -> bool:
    return len(word) > 1 and bool(_checker.unknown([word.lower()]))


def suggestions(word: str) -> list[str]:
    candidates = _checker.candidates(word.lower())
    return sorted(candidates)[:5] if candidates else []


def _match_case(original: str, corrected: str) -> str:
    return corrected[:1].upper() + corrected[1:] if original[:1].isupper() else corrected


def autocorrect_word(word: str) -> str | None:
    """Return a corrected form of `word` if one is known, else None. Checks
    the curated contraction/typo map first, then falls back to the
    spellchecker's own best guess for otherwise-misspelled words."""
    lower = word.lower()
    if lower in AUTOCORRECT_MAP:
        return _match_case(word, AUTOCORRECT_MAP[lower])
    if is_misspelled(word):
        guess = _checker.correction(lower)
        if guess and guess != lower:
            return _match_case(word, guess)
    return None


def word_at(text: str, position: int) -> tuple[str, int, int] | None:
    """Find the word (and its [start, end) span) containing `position`, if any."""
    for match in _WORD_RE.finditer(text):
        if match.start() <= position <= match.end():
            return match.group(), match.start(), match.end()
    return None


def word_ending_at(text: str, end_position: int) -> tuple[str, int, int] | None:
    """Find the word (and its [start, end) span) whose end is exactly
    `end_position` -- used to autocorrect the word just finished when a
    boundary character (space, punctuation, Enter) is typed."""
    for match in _WORD_RE.finditer(text):
        if match.end() == end_position:
            return match.group(), match.start(), match.end()
    return None
