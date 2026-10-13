"""Shared state handed to every detector for one analysis."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..email_processing.normalizer import NormalisedText, normalise
from ..email_processing.parser import ParsedEmail
from .evidence import Collector


@dataclass
class Profile:
    id: int
    kind: str          # vip | vendor
    name: str
    emails: list[str]
    domains: list[str]


@dataclass
class AnalysisContext:
    parsed: ParsedEmail
    org_domains: list[str]
    trusted_authserv_ids: list[str]
    profiles: list[Profile] = field(default_factory=list)
    sender_history_count: int = 0      # prior retained analyses from the same sender address
    collector: Collector = field(default_factory=Collector)
    subject_n: NormalisedText | None = None
    body_n: NormalisedText | None = None
    tactics: dict[str, list[str]] = field(default_factory=dict)        # tactic -> finding ids
    actions: dict[str, list[str]] = field(default_factory=dict)        # requested action -> finding ids
    phones: list[str] = field(default_factory=list)
    bank_refs: list[str] = field(default_factory=list)
    reputation: list[dict] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.subject_n = normalise(self.parsed.subject or "")
        self.body_n = normalise(self.parsed.visible_text or "")

    @property
    def fields(self) -> list[tuple[str, NormalisedText]]:
        return [("subject", self.subject_n), ("body", self.body_n)]  # type: ignore[list-item]
