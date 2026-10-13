"""Evasion-aware normalisation that keeps an original→normalised offset map.

Detects (and records the locations of) zero-width characters, soft hyphens, bidi controls,
HTML entity leftovers and mixed-script homoglyph words, then produces normalised text for the
detectors. The original string is never modified, so evidence of the evasion is preserved.
"""
from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = {"​": "ZERO WIDTH SPACE", "‌": "ZERO WIDTH NON-JOINER", "‍": "ZERO WIDTH JOINER",
              "⁠": "WORD JOINER", "﻿": "ZERO WIDTH NO-BREAK SPACE", "­": "SOFT HYPHEN",
              "᠎": "MONGOLIAN VOWEL SEPARATOR"}
BIDI = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩", "‎", "‏"}
# Common Cyrillic/Greek look-alikes of Latin letters (subset of Unicode confusables).
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ԝ": "w", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y", "α": "a", "ο": "o", "ρ": "p", "ν": "v",
    "τ": "t", "Ι": "I", "Ο": "O", "Ρ": "P", "Α": "A", "Β": "B", "Ε": "E", "Κ": "K", "Μ": "M", "Ν": "N", "Τ": "T",
}
_WORD = re.compile(r"\w+", re.UNICODE)


@dataclass
class EvasionMark:
    kind: str  # zero_width | bidi_control | homoglyph_word | html_entity
    position: int
    detail: str


@dataclass
class NormalisedText:
    original: str
    text: str
    offsets: list[int]  # offsets[i] = index in original for char i of normalised text
    marks: list[EvasionMark] = field(default_factory=list)

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        if not self.offsets:
            return start, end
        s = self.offsets[min(start, len(self.offsets) - 1)]
        e = self.offsets[min(max(end - 1, 0), len(self.offsets) - 1)] + 1
        return s, e


def _script(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "OTHER"
    for s in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN"):
        if name.startswith(s):
            return s
    return "OTHER"


def normalise(original: str) -> NormalisedText:
    marks: list[EvasionMark] = []
    # entity leftovers (e.g. "&#112;assword") are decoded but marked
    for m in re.finditer(r"&(#\d{2,6}|#x[0-9a-fA-F]{2,6}|[a-zA-Z]{2,8});", original):
        if m.group(0) not in ("&amp;", "&nbsp;", "&lt;", "&gt;", "&quot;"):
            marks.append(EvasionMark("html_entity", m.start(), m.group(0)))
    out_chars: list[str] = []
    offsets: list[int] = []
    i = 0
    src = original
    while i < len(src):
        ch = src[i]
        if ch == "&":
            m = re.match(r"&(#\d{2,6}|#x[0-9a-fA-F]{2,6}|[a-zA-Z]{2,8});", src[i:])
            if m:
                dec = html.unescape(m.group(0))
                for c in dec:
                    out_chars.append(c)
                    offsets.append(i)
                i += len(m.group(0))
                continue
        if ch in ZERO_WIDTH:
            marks.append(EvasionMark("zero_width", i, ZERO_WIDTH[ch]))
            i += 1
            continue
        if ch in BIDI:
            marks.append(EvasionMark("bidi_control", i, f"U+{ord(ch):04X}"))
            i += 1
            continue
        nf = unicodedata.normalize("NFKC", ch)
        for c in nf:
            out_chars.append(c)
            offsets.append(i)
        i += 1
    text = "".join(out_chars)
    # homoglyph words: words mixing Latin with Cyrillic/Greek look-alikes
    fixed = list(text)
    for m in _WORD.finditer(text):
        w = m.group(0)
        scripts = {_script(c) for c in w if c.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK", "ARMENIAN"}:
            repl = "".join(CONFUSABLES.get(c, c) for c in w)
            marks.append(EvasionMark("homoglyph_word", offsets[m.start()] if offsets else m.start(), f"{w} → {repl}"))
            for k, c in enumerate(repl):
                fixed[m.start() + k] = c
        elif scripts and scripts <= {"CYRILLIC", "GREEK"} and all(c in CONFUSABLES for c in w if c.isalpha()) and len(w) >= 4:
            repl = "".join(CONFUSABLES.get(c, c) for c in w)
            marks.append(EvasionMark("homoglyph_word", offsets[m.start()] if offsets else m.start(), f"{w} → {repl}"))
            for k, c in enumerate(repl):
                fixed[m.start() + k] = c
    return NormalisedText(original=original, text="".join(fixed), offsets=offsets, marks=marks)


def skeleton(s: str) -> str:
    """Confusable skeleton for domain/display-name comparison."""
    s = unicodedata.normalize("NFKC", s.lower())
    s = "".join(CONFUSABLES.get(c, c) for c in s)
    s = s.replace("rn", "m").replace("vv", "w").replace("0", "o").replace("1", "l").replace("|", "l")
    return s.translate(dict.fromkeys(map(ord, "".join(ZERO_WIDTH) + "".join(BIDI)), None))
