"""Turn deceptive spellings back into plain Latin so they can be compared.

Covers the tricks seen in real phishing domains:
  * homoglyphs: Cyrillic/Greek letters that look Latin (biаt with a Cyrillic "а")
  * accents: bíat, attïjari
  * leetspeak: b1at, amenb4nk, 0oredoo
  * multi-letter lookalikes: "rn" for "m", "vv" for "w"
"""

from __future__ import annotations

import unicodedata

# Subset of the Unicode confusables table relevant to Latin brand names.
CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "һ": "h",
    "і": "i", "ї": "i", "ј": "j", "к": "k", "ӏ": "l", "м": "m", "н": "h",
    "о": "o", "р": "p", "ԛ": "q", "ѕ": "s", "т": "t", "у": "y", "ѡ": "w",
    "х": "x", "ү": "y", "ɡ": "g", "ь": "b", "п": "n", "г": "r",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ϲ": "c",
    # Latin extensions and IPA
    "ı": "i", "ɩ": "i", "ł": "l", "ƚ": "l", "ɑ": "a", "ɒ": "a", "ʀ": "r",
    "ꞵ": "b", "ƅ": "b", "đ": "d", "ð": "d", "ħ": "h", "ŧ": "t", "ø": "o",
    "œ": "oe", "æ": "ae", "ß": "ss",
    # Armenian
    "օ": "o", "ս": "u", "ց": "g", "հ": "h",
}

# Leetspeak. "1" is ambiguous (i or l) so it produces two variants.
LEET_COMMON = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s"}

MULTI_LETTER = (("rn", "m"), ("vv", "w"), ("cl", "d"))


def fold(text: str) -> str:
    """NFKC, lowercase, strip accents and map confusable characters."""
    text = unicodedata.normalize("NFKC", text).lower()
    text = "".join(CONFUSABLES.get(ch, ch) for ch in text)
    decomposed = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return "".join(CONFUSABLES.get(ch, ch) for ch in text)


def leet_variants(text: str) -> set[str]:
    base = "".join(LEET_COMMON.get(ch, ch) for ch in text)
    if "1" not in base:
        return {base}
    return {base.replace("1", "i"), base.replace("1", "l")}


def multi_letter_variants(text: str) -> set[str]:
    out = {text}
    for a, b in MULTI_LETTER:
        for v in list(out):
            if a in v:
                out.add(v.replace(a, b))
    return out


def skeletons(text: str) -> set[str]:
    """All plausible plain-Latin readings of `text` (excluding `text` itself
    when nothing changed)."""
    folded = fold(text)
    results: set[str] = set()
    for v in leet_variants(folded):
        results |= multi_letter_variants(v)
    results.add(folded)
    return results


def compact(text: str) -> str:
    """Remove separators: "biat-secure.login" -> "biatsecurelogin"."""
    return "".join(ch for ch in text if ch not in ".-_~")
