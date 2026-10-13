"""Text preprocessing shared by training (scripts/) and live inference (backend).

The single source of truth for how text is turned into model input, so training and
serving cannot drift apart.

MeAJOR bodies are anonymised with entity placeholders such as ``[NAME]`` or ``<|URL|>``.
Live emails are not. To keep train/serve distributions comparable we:

* map placeholders we *can* reproduce at inference time (URL, e-mail address, phone
  number, IP address) to canonical tokens, and apply the same regex substitution to
  live text;
* drop placeholders that depend on the dataset authors' NER (``[NAME]``,
  ``[ORGANIZATION]``, ``[DATE]`` ...), because we cannot reproduce them on live mail.
"""
from __future__ import annotations

import re
import unicodedata

PREP_VERSION = "textprep-1.0"
MAX_MODEL_CHARS = 12_000

# Placeholders present in MeAJOR (documented in the Zenodo record + observed in data).
_REPRODUCIBLE_PLACEHOLDERS = [
    (re.compile(r"<\|\s*\[*\s*URL\s*\]*\s*\|>|\[URL\]", re.I), " urltoken "),
    (re.compile(r"<\|\s*\[*\s*EMAIL_ADDRESS\s*\]*\s*\|>|\[EMAIL_ADDRESS\]", re.I), " emailtoken "),
    (re.compile(r"<\|\s*\[*\s*PHONE(?:_NUMBER)?\s*\]*\s*\|>|\[PHONE_NUMBER\]", re.I), " phonetoken "),
    (re.compile(r"<\|\s*\[*\s*IP_ADDRESS\s*\]*\s*\|>|\[IP_ADDRESS\]", re.I), " iptoken "),
]
_OTHER_PLACEHOLDERS = re.compile(
    r"<\|\s*\[*\s*[A-Z_]{2,30}\s*\]*\s*\|>|\[(?:PGP|EMOJI|SYMBOL|NAME|USERNAME|INITIALS|ADDRESS|ORGANIZATION|"
    r"FILE_PATH|FILE_NAME|FILE|DATE|TIME|FINANCIAL_INFO|PRODUCT|REFERENCE_NUMBER)\]"
)

# Live-text equivalents.
_URL_RE = re.compile(r"\b(?:https?://|hxxps?://|www\.)[^\s<>\"')\]]+", re.I)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3,4}[\s.-]\d{3,4}(?:[\s.-]\d{2,4})?(?!\w)")

_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿­‪‫‬‭‮⁦⁧⁨⁩"), None)
_REPEAT_TOKEN = re.compile(r"\b(urltoken|emailtoken|phonetoken|iptoken)(?:\s+\1\b)+")
_WS = re.compile(r"\s+")


def normalise_common(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = text.translate(_INVISIBLE)
    return text


def prep_dataset_text(subject: str | None, body: str | None) -> str:
    """Prepare an anonymised MeAJOR-style record."""
    t = f"{subject or ''}\n{body or ''}"
    t = normalise_common(t)
    for rx, tok in _REPRODUCIBLE_PLACEHOLDERS:
        t = rx.sub(tok, t)
    t = _OTHER_PLACEHOLDERS.sub(" ", t)
    # raw (non-anonymised) supplementary corpora may still contain live URLs etc.
    t = _replace_live_entities(t)
    return _finish(t)


def prep_live_text(subject: str | None, body: str | None) -> str:
    """Prepare a live email (subject + visible body) for the trained model."""
    t = normalise_common(f"{subject or ''}\n{body or ''}")
    t = _replace_live_entities(t)
    return _finish(t)


def _replace_live_entities(t: str) -> str:
    t = _URL_RE.sub(" urltoken ", t)
    t = _EMAIL_RE.sub(" emailtoken ", t)
    t = _IP_RE.sub(" iptoken ", t)
    t = _PHONE_RE.sub(" phonetoken ", t)
    return t


def _finish(t: str) -> str:
    t = t.lower()
    t = _WS.sub(" ", t).strip()
    t = _REPEAT_TOKEN.sub(r"\1", t)
    return t[:MAX_MODEL_CHARS]


CHAR_FEATURE_CHARS = 4_000


def truncate_for_char(text: str) -> str:
    """Preprocessor for the character n-gram vectoriser (bounded cost on long emails)."""
    return text[:CHAR_FEATURE_CHARS]
