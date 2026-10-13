"""Safe .eml / pasted-text parsing.

* Never executes or renders anything: attachments are hashed and typed by magic bytes only.
* Enforces size / part-count / nesting limits; violations are recorded as stage failures.
* Preserves the raw input separately (sha256 + optional retained copy) from normalised text.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import Any

from .html_inspector import HtmlReport, inspect_html

MAX_PARTS = 200
MAX_DEPTH = 10
MAX_ATTACHMENT_TEXT = 200_000
TEXT_ATTACHMENT_TYPES = {"text/plain", "text/html", "text/csv", "text/calendar"}

_HEADER_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,40}:\s?.*$")
_KNOWN_HEADERS = {"from", "to", "subject", "date", "reply-to", "return-path", "received", "message-id",
                  "cc", "mime-version", "content-type", "authentication-results", "x-mailer", "in-reply-to",
                  "references", "delivered-to", "sender"}


@dataclass
class Attachment:
    index: int
    filename: str
    declared_type: str
    detected_type: str
    extension: str
    size: int
    sha256: str
    text_extraction_status: str  # extracted | not_supported | too_large | failed
    extracted_text: str = ""
    location: str = ""


@dataclass
class UrlRef:
    url: str
    source_location: str
    anchor_text: str = ""


@dataclass
class ParsedEmail:
    input_source: str
    raw_sha256: str
    raw_size: int
    headers_present: bool
    headers: dict[str, Any] = field(default_factory=dict)
    from_display: str = ""
    from_addr: str = ""
    from_domain: str = ""
    reply_to_addr: str = ""
    reply_to_domain: str = ""
    return_path_domain: str = ""
    to_addrs: list[str] = field(default_factory=list)
    subject: str = ""
    date_iso: str | None = None
    message_id: str = ""
    in_reply_to: str = ""
    references: str = ""
    auth_results: list[str] = field(default_factory=list)
    received_count: int = 0
    text_body: str = ""
    html_body: str = ""
    html: HtmlReport | None = None
    visible_text: str = ""
    parts: list[dict] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    urls: list[UrlRef] = field(default_factory=list)
    defects: list[str] = field(default_factory=list)
    stage_status: dict[str, dict] = field(default_factory=dict)

    def summary(self) -> dict:
        return {
            "input_source": self.input_source,
            "headers_present": self.headers_present,
            "from_display": self.from_display,
            "from_addr": self.from_addr,
            "from_domain": self.from_domain,
            "reply_to_addr": self.reply_to_addr,
            "reply_to_domain": self.reply_to_domain,
            "return_path_domain": self.return_path_domain,
            "to": self.to_addrs[:20],
            "subject": self.subject,
            "date": self.date_iso,
            "message_id": self.message_id,
            "in_reply_to": self.in_reply_to,
            "has_references": bool(self.references),
            "authentication_results": self.auth_results[:5],
            "received_hops": self.received_count,
            "parts": self.parts[:50],
            "attachments": [{k: v for k, v in a.__dict__.items() if k != "extracted_text"} for a in self.attachments],
            "url_count": len(self.urls),
            "html_present": bool(self.html_body),
            "hidden_segment_count": len(self.html.hidden_segments) if self.html else 0,
            "defects": self.defects[:20],
            "raw_sha256": self.raw_sha256,
            "raw_size": self.raw_size,
        }


class EmailParseError(ValueError):
    pass


def looks_like_rfc822(text: str) -> bool:
    """Pasted text is treated as a full message only if it starts with a real header block."""
    lines = text.lstrip("﻿").splitlines()
    names = []
    for line in lines[:60]:
        if not line.strip():
            break
        if line[:1] in (" ", "\t"):
            continue
        if not _HEADER_LINE.match(line):
            return False
        names.append(line.split(":", 1)[0].lower())
    return len(names) >= 2 and len(set(names) & _KNOWN_HEADERS) >= 2


def parse_input(raw: bytes, input_source: str, max_bytes: int,
                subject: str | None = None, sender: str | None = None) -> ParsedEmail:
    if len(raw) > max_bytes:
        raise EmailParseError(f"input is {len(raw)} bytes; limit is {max_bytes}")
    if not raw.strip():
        raise EmailParseError("input is empty")
    sha = hashlib.sha256(raw).hexdigest()
    text_guess = raw.decode("utf-8", errors="replace")
    if input_source == "eml" or looks_like_rfc822(text_guess):
        pe = _parse_mime(raw, input_source, sha)
    else:
        pe = ParsedEmail(input_source=input_source, raw_sha256=sha, raw_size=len(raw), headers_present=False)
        body = text_guess
        if "<html" in body.lower() or re.search(r"<(div|p|span|table|a)\b", body, re.I):
            pe.html_body = body
        else:
            pe.text_body = body
        pe.stage_status["mime"] = {"status": "skipped", "detail": "pasted body without a header block"}
    if subject and not pe.subject:
        pe.subject = subject.strip()[:500]
    if sender and not pe.from_addr:
        disp, addr = parseaddr(sender)
        pe.from_display, pe.from_addr = disp, addr.lower()
        pe.from_domain = _domain(addr)
        pe.headers["from"] = sender
    _finalise_bodies(pe)
    return pe


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1].strip().strip(">").lower() if "@" in addr else ""


def _parse_mime(raw: bytes, input_source: str, sha: str) -> ParsedEmail:
    try:
        msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # pragma: no cover - stdlib parser is very lenient
        raise EmailParseError(f"MIME parse failed: {exc}") from exc
    pe = ParsedEmail(input_source=input_source, raw_sha256=sha, raw_size=len(raw), headers_present=True)

    def h(name: str) -> str:
        try:
            v = msg.get(name)
            return str(v) if v is not None else ""
        except Exception as exc:  # malformed header value
            pe.defects.append(f"header {name}: {type(exc).__name__}")
            raw_v = msg.get_all(name, failobj=[""])
            return str(raw_v[0]) if raw_v else ""

    frm = h("From")
    pe.from_display, addr = parseaddr(frm)
    pe.from_addr = addr.lower()
    pe.from_domain = _domain(pe.from_addr)
    rt = h("Reply-To")
    if rt:
        pe.reply_to_addr = parseaddr(rt)[1].lower()
        pe.reply_to_domain = _domain(pe.reply_to_addr)
    rp = h("Return-Path")
    if rp:
        pe.return_path_domain = _domain(parseaddr(rp)[1].lower())
    pe.to_addrs = [a.lower() for _, a in getaddresses([h("To"), h("Cc")]) if a]
    pe.subject = h("Subject")[:500]
    d = h("Date")
    if d:
        try:
            pe.date_iso = parsedate_to_datetime(d).isoformat()
        except Exception:
            pe.defects.append("unparseable Date header")
    pe.message_id = h("Message-ID")[:300]
    pe.in_reply_to = h("In-Reply-To")[:300]
    pe.references = h("References")[:2000]
    pe.auth_results = [str(v)[:1000] for v in (msg.get_all("Authentication-Results") or [])]
    pe.received_count = len(msg.get_all("Received") or [])
    pe.headers = {"from": frm, "reply-to": rt, "return-path": rp, "to": h("To")[:500], "subject": pe.subject,
                  "date": d, "message-id": pe.message_id, "x-mailer": h("X-Mailer")[:200]}
    for defect in getattr(msg, "defects", []):
        pe.defects.append(type(defect).__name__)

    text_parts: list[str] = []
    html_parts: list[str] = []
    count = 0
    stage = {"status": "ok", "detail": ""}

    def walk(part: EmailMessage, path: str, depth: int) -> None:
        nonlocal count
        count += 1
        if count > MAX_PARTS:
            stage.update(status="partial", detail=f"more than {MAX_PARTS} MIME parts; remainder skipped")
            return
        if depth > MAX_DEPTH:
            stage.update(status="partial", detail=f"MIME nesting deeper than {MAX_DEPTH}; remainder skipped")
            return
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        filename = part.get_filename()
        pe.parts.append({"path": path, "content_type": ctype, "disposition": disp or "",
                         "filename": _safe_name(filename) if filename else "",
                         "charset": part.get_content_charset() or "",
                         "transfer_encoding": str(part.get("Content-Transfer-Encoding", "")).lower()})
        if part.is_multipart():
            for i, sub in enumerate(part.iter_parts()):
                walk(sub, f"{path}.{i}", depth + 1)
            return
        if ctype == "message/rfc822":
            # nested message: treat as attachment-like, do not recurse into its execution
            payload = part.get_payload()
            if isinstance(payload, list):
                for i, sub in enumerate(payload):
                    walk(sub, f"{path}.{i}", depth + 1)
            return
        if disp == "attachment" or (filename and ctype not in ("text/plain", "text/html")):
            pe.attachments.append(_attachment(part, len(pe.attachments), path, filename))
            return
        if ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:
                data = part.get_payload(decode=True) or b""
                content = data.decode(part.get_content_charset() or "utf-8", errors="replace")
                pe.defects.append(f"part {path}: charset decode fallback")
            (html_parts if ctype == "text/html" else text_parts).append(content)
        elif filename or part.get_payload(decode=True):
            pe.attachments.append(_attachment(part, len(pe.attachments), path, filename))

    walk(msg, "0", 0)
    pe.text_body = "\n".join(text_parts)
    pe.html_body = "\n".join(html_parts)
    pe.stage_status["mime"] = stage
    return pe


_MAGIC = [
    (b"MZ", "application/x-dosexec"),
    (b"%PDF", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    (b"\x89PNG", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"Rar!", "application/x-rar"),
    (b"7z\xbc\xaf", "application/x-7z-compressed"),
    (b"\x1f\x8b", "application/gzip"),
    (b"{\\rtf", "application/rtf"),
]


def detect_type(data: bytes) -> str:
    for sig, t in _MAGIC:
        if data.startswith(sig):
            return t
    if data[:6] == b"\x00\x00\x00\x00\x00\x00":
        return "unknown"
    head = data[:2048]
    if b"\x00" not in head:
        low = head.lower()
        if b"<html" in low or b"<!doctype html" in low or b"<form" in low:
            return "text/html"
        if b"<svg" in low:
            return "image/svg+xml"
        return "text/plain"
    if len(data) >= 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "application/x-iso9660-image"
    return "application/octet-stream"


def _safe_name(name: str) -> str:
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f]", "", name)
    return name[:255]


def _attachment(part: EmailMessage, index: int, path: str, filename: str | None) -> Attachment:
    data = part.get_payload(decode=True) or b""
    fname = _safe_name(filename or f"unnamed-part-{path}")
    ext = fname.rsplit(".", 1)[1].lower() if "." in fname else ""
    detected = detect_type(data)
    status, text = "not_supported", ""
    declared = part.get_content_type()
    if detected in ("text/plain", "text/html") or declared in TEXT_ATTACHMENT_TYPES:
        if len(data) > MAX_ATTACHMENT_TEXT:
            status = "too_large"
        else:
            try:
                text = data.decode(part.get_content_charset() or "utf-8", errors="replace")
                status = "extracted"
            except Exception:
                status = "failed"
    return Attachment(index=index, filename=fname, declared_type=declared, detected_type=detected, extension=ext,
                      size=len(data), sha256=hashlib.sha256(data).hexdigest(), text_extraction_status=status,
                      extracted_text=text, location=f"attachment[{index}] mime:{path}")


def _finalise_bodies(pe: ParsedEmail) -> None:
    if pe.html_body:
        try:
            pe.html = inspect_html(pe.html_body)
            pe.stage_status["html"] = {"status": "ok", "detail": f"{len(pe.html.hidden_segments)} hidden segment(s)"}
        except Exception as exc:
            pe.stage_status["html"] = {"status": "failed", "detail": type(exc).__name__}
    else:
        pe.stage_status["html"] = {"status": "not_applicable", "detail": "no HTML body"}
    if pe.text_body.strip():
        pe.visible_text = pe.text_body
    elif pe.html:
        pe.visible_text = pe.html.visible_text
    # URLs: HTML anchors first (with anchor text), then plain-text URLs
    from .urls import extract_urls  # local import to avoid cycle
    seen: set[str] = set()
    if pe.html:
        for i, a in enumerate(pe.html.anchors):
            if a["href"] and a["href"] not in seen:
                seen.add(a["href"])
                pe.urls.append(UrlRef(a["href"], f"html:anchor[{i}]", a["text"][:200]))
    for field_name, txt in (("body:text", pe.text_body), ("body:html-visible", pe.html.visible_text if pe.html else "")):
        for u, start in extract_urls(txt):
            if u not in seen:
                seen.add(u)
                pe.urls.append(UrlRef(u, f"{field_name}[{start}:{start + len(u)}]"))
    pe.urls = pe.urls[:300]
    pe.stage_status["parse"] = {"status": "ok", "detail": f"{len(pe.urls)} URL(s), {len(pe.attachments)} attachment(s)"}
