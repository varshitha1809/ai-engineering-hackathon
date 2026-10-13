"""Indicator extraction/normalisation for the IOC store and campaign correlation."""
from __future__ import annotations

import hashlib

from ..analysis.context import AnalysisContext
from ..analysis.detectors.identity import FREEMAIL
from ..email_processing.urls import normalise_url

# Infrastructure that is shared by huge numbers of unrelated senders; matching on it is not campaign evidence.
COMMON_DOMAINS = FREEMAIL | {"google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com", "twitter.com", "x.com",
                             "linkedin.com", "youtube.com", "instagram.com", "w3.org", "schemas.microsoft.com", "office.com",
                             "outlook.com", "live.com", "gstatic.com", "googleapis.com", "cloudfront.net", "akamaihd.net",
                             "doubleclick.net", "mailchimp.com", "list-manage.com", "sendgrid.net", "wikipedia.org", "github.com",
                             "zoom.us", "dropbox.com", "bit.ly"}


def _h(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:32]


def extract(ctx: AnalysisContext) -> list[dict]:
    pe = ctx.parsed
    out: list[dict] = []
    seen = set()

    def add(t: str, value: str, display: str, location: str, correlate: bool = True):
        if not value:
            return
        key = (t, value, location)
        if key in seen:
            return
        seen.add(key)
        out.append({"type": t, "value": value, "display_value": display[:300], "location": location, "correlate": correlate})

    for i, ref in enumerate(pe.urls):
        n = normalise_url(ref.url)
        if not n.valid or not n.host:
            continue
        add("url", n.normalised.lower(), n.normalised, f"url[{i}]")
        add("domain", n.registrable_domain, n.registrable_domain, f"url[{i}]", n.registrable_domain not in COMMON_DOMAINS)
    for a in pe.attachments:
        add("sha256", a.sha256, f"{a.filename} ({a.sha256[:12]}…)", a.location)
    if pe.from_addr:
        add("sender_address", pe.from_addr, pe.from_addr, "header:From")
        add("sender_domain", pe.from_domain, pe.from_domain, "header:From", pe.from_domain not in COMMON_DOMAINS)
    if pe.reply_to_addr and pe.reply_to_addr != pe.from_addr:
        add("reply_to_address", pe.reply_to_addr, pe.reply_to_addr, "header:Reply-To")
        add("reply_to_domain", pe.reply_to_domain, pe.reply_to_domain, "header:Reply-To", pe.reply_to_domain not in COMMON_DOMAINS)
    for p in ctx.phones:
        add("phone", _h(p), f"…{p[-4:]} (masked)", "body")
    for b in ctx.bank_refs:
        add("bank_account", _h(b), f"…{b[-4:]} (masked)", "body")
    return out
