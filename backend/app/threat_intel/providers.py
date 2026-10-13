"""Threat-intelligence provider adapters.

* LocalIndicatorProvider — always available; reads the application's own IOC table. Results carry
  the record's source label (e.g. "local demo list", "analyst-confirmed").
* VirusTotalProvider — optional. Used only when PHISHDNA_ENABLE_EXTERNAL_LOOKUPS=true *and* an API
  key is configured (sending indicators to a third party is a data transfer). Has timeout, cache
  and a simple rate limit. Unknown/empty responses map to "unknown", never to clean or malicious.
"""
from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

import httpx


@dataclass
class TIResult:
    indicator_type: str
    value: str
    provider: str
    verdict: str          # malicious | suspicious | clean | unknown | error
    source: str
    checked_at: str
    detail: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class Provider(Protocol):
    name: str

    def available(self) -> tuple[bool, str]: ...

    def lookup(self, indicator_type: str, value: str) -> TIResult: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalIndicatorProvider:
    name = "local"

    def __init__(self, db):
        self.db = db

    def available(self) -> tuple[bool, str]:
        return True, "local IOC table"

    def lookup(self, indicator_type: str, value: str) -> TIResult:
        row = self.db.one(
            "SELECT reputation, reputation_source, review_status, expires_at FROM indicators "
            "WHERE type=? AND value=? AND reputation IS NOT NULL AND reputation != 'unknown'", (indicator_type, value))
        if not row:
            return TIResult(indicator_type, value, self.name, "unknown", "no local record", _now())
        if row["expires_at"] and row["expires_at"] < _now():
            return TIResult(indicator_type, value, self.name, "unknown", row["reputation_source"] or "local", _now(),
                            "local record expired - needs review")
        if row["review_status"] == "pending_review":
            return TIResult(indicator_type, value, self.name, "unknown", row["reputation_source"] or "local", _now(),
                            f"unreviewed local report ({row['reputation']}) - not treated as established")
        return TIResult(indicator_type, value, self.name, row["reputation"], row["reputation_source"] or "local", _now())


class VirusTotalProvider:
    name = "virustotal"
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, enabled: bool, timeout: float = 6.0, per_minute: int = 4):
        self.api_key = api_key
        self.enabled = enabled
        self.timeout = timeout
        self.per_minute = per_minute
        self._calls: list[float] = []
        self._cache: dict[tuple[str, str], tuple[float, TIResult]] = {}

    def available(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "not configured (PHISHDNA_ENABLE_EXTERNAL_LOOKUPS is false)"
        if not self.api_key:
            return False, "not configured (VIRUSTOTAL_API_KEY missing)"
        return True, "configured (connectivity not verified until first lookup)"

    def lookup(self, indicator_type: str, value: str) -> TIResult:
        ok, why = self.available()
        if not ok:
            return TIResult(indicator_type, value, self.name, "unknown", why, _now())
        key = (indicator_type, value)
        if key in self._cache and time.time() - self._cache[key][0] < 3600:
            return self._cache[key][1]
        now = time.time()
        self._calls = [t for t in self._calls if now - t < 60]
        if len(self._calls) >= self.per_minute:
            return TIResult(indicator_type, value, self.name, "unknown", "rate limit reached locally", _now())
        self._calls.append(now)
        if indicator_type == "url":
            path = "/urls/" + base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        elif indicator_type == "domain":
            path = f"/domains/{value}"
        elif indicator_type == "sha256":
            path = f"/files/{value}"  # hash lookup only; files are never uploaded
        else:
            return TIResult(indicator_type, value, self.name, "unknown", "type not supported by provider", _now())
        try:
            r = httpx.get(self.BASE + path, headers={"x-apikey": self.api_key}, timeout=self.timeout)
            if r.status_code == 404:
                res = TIResult(indicator_type, value, self.name, "unknown", "virustotal", _now(), "not found")
            elif r.status_code != 200:
                res = TIResult(indicator_type, value, self.name, "error", "virustotal", _now(), f"HTTP {r.status_code}")
            else:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
                verdict = "malicious" if mal >= 3 else "suspicious" if (mal + sus) >= 1 else ("clean" if stats else "unknown")
                res = TIResult(indicator_type, value, self.name, verdict, "virustotal", _now(),
                               f"malicious={mal} suspicious={sus} harmless={stats.get('harmless', 0)}")
        except httpx.HTTPError as exc:
            res = TIResult(indicator_type, value, self.name, "error", "virustotal", _now(), f"{type(exc).__name__}")
        self._cache[key] = (time.time(), res)
        return res
