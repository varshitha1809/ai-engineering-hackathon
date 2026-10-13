"""Audit trail. Details are redacted: no secrets, no email bodies."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..db import Database

_SECRETISH = re.compile(r"(api[_-]?key|token|secret|password)\s*[=:]\s*\S+", re.I)


def redact(text: str) -> str:
    text = _SECRETISH.sub(r"\1=[redacted]", text or "")
    text = re.sub(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", "[email]", text)
    return text[:500]


def audit(db: Database, action: str, actor: str, target_type: str, target_id: str, outcome: str, detail: str = "") -> None:
    db.insert("audit_events", {"ts": datetime.now(timezone.utc).isoformat(), "action": action, "actor": actor or "local-analyst",
                               "target_type": target_type, "target_id": target_id, "outcome": outcome, "detail": redact(detail)})
