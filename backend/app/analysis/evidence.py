"""Evidence record (spec §6.4) and the per-analysis collector."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    finding_id: str
    category: str               # e.g. identity.reply_to_mismatch
    component: str              # fusion group: text_model|intent|identity|url|attachment|ai_injection|reputation|evasion|context|coverage
    severity: str               # info|low|medium|high|critical
    title: str
    observed_value: str         # safe excerpt / value (bounded)
    source_location: str        # header:Reply-To, body[120:168], html:div[2]>span[1], url[0], attachment[1] ...
    method: str                 # model|rule|provider
    version: str
    confidence: float           # strength of this evidence 0..1 (not a probability)
    status: str                 # observed|inferred|unavailable
    explanation: str
    timestamp: str = field(default_factory=now_iso)
    related_indicator_ids: list[Any] = field(default_factory=list)   # filled at persistence (indicator table ids)
    related_finding_ids: list[str] = field(default_factory=list)     # findings this inference is built on
    span: dict | None = None    # {"field": "subject"|"body", "start": int, "end": int} for highlighting
    tags: list[str] = field(default_factory=list)
    analysis_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


_IBAN_RX = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,3})?\b")
_LONGNUM_RX = re.compile(r"(?<![\w+])\d(?:[\d \-]{6,22})\d(?![\w])")


def mask_numbers(text: str) -> str:
    """Mask IBANs and account-like digit runs in evidence excerpts (keep last 4 for correlation by eye)."""
    def m(x: re.Match) -> str:
        digits = re.sub(r"\D", "", x.group(0))
        if len(digits) < 8:
            return x.group(0)
        return f"[number …{digits[-4:]}]"
    text = _IBAN_RX.sub(lambda x: f"[IBAN …{re.sub(r'[^0-9A-Z]', '', x.group(0))[-4:]}]", text)
    return _LONGNUM_RX.sub(m, text)


def excerpt(text: str, start: int, end: int, pad: int = 40, limit: int = 240) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    # widen to whole numbers/tokens so a window edge cannot split an account number past the masker
    while s > 0 and (text[s - 1].isalnum() or (text[s - 1] in " -" and s > 1 and text[s - 2].isdigit())):
        s -= 1
    while e < len(text) and (text[e].isalnum() or (text[e] in " -" and e + 1 < len(text) and text[e + 1].isdigit())):
        e += 1
    frag = mask_numbers(text[s:e].replace("\n", " "))
    if len(frag) > limit:
        frag = frag[:limit] + "…"
    return ("…" if s > 0 else "") + frag + ("…" if e < len(text) else "")


class Collector:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add(self, *, category: str, component: str, severity: str, title: str, observed_value: str,
            source_location: str, method: str, version: str, confidence: float, status: str, explanation: str,
            span: dict | None = None, tags: list[str] | None = None, related: list[Any] | None = None) -> Finding:
        f = Finding(finding_id=f"F{len(self.findings) + 1:03d}", category=category, component=component,
                    severity=severity, title=title, observed_value=(observed_value or "")[:500],
                    source_location=source_location, method=method, version=version,
                    confidence=round(float(confidence), 3), status=status, explanation=explanation,
                    span=span, tags=tags or [], related_finding_ids=related or [])
        self.findings.append(f)
        return f

    def by_component(self, component: str, status: str | None = None) -> list[Finding]:
        return [f for f in self.findings if f.component == component and (status is None or f.status == status)]
