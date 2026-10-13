"""URL extraction and static normalisation. The backend never fetches these URLs (no SSRF surface)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

_URL_RE = re.compile(r"\b(?:https?://|hxxps?://|www\.)[^\s<>\"'\])]+", re.I)
_TRAILING = ".,;:!?)]}'\""

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in", "org.in", "gov.in",
    "ac.in", "co.jp", "co.nz", "com.br", "com.cn", "com.mx", "co.za", "com.sg", "com.tr", "co.kr", "com.hk",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
                  "shorturl.at", "rb.gy", "tiny.cc", "s.id"}
# Weak signal only: TLDs that are frequently abused per public abuse reporting; never decisive on their own.
ABUSED_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest", "cam",
               "support", "icu", "cyou", "sbs", "quest"}


def extract_urls(text: str) -> list[tuple[str, int]]:
    out = []
    for m in _URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(_TRAILING)
        out.append((u, m.start()))
    return out


@dataclass
class NormalisedUrl:
    original: str
    normalised: str
    scheme: str
    host: str  # lower-case, IDNA-decoded when punycode
    host_ascii: str
    registrable_domain: str
    path: str
    is_ip: bool
    has_userinfo: bool
    port: int | None
    valid: bool
    error: str = ""


def registrable_domain(host: str) -> str:
    host = host.strip(".").lower()
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def normalise_url(url: str) -> NormalisedUrl:
    raw = url.strip()
    u = raw
    if u.lower().startswith("hxxp"):
        u = "http" + u[4:]
    if u.lower().startswith("www."):
        u = "http://" + u
    try:
        parts = urlsplit(u)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as exc:
        return NormalisedUrl(raw, raw, "", "", "", "", "", False, False, None, False, f"malformed: {exc}")
    if not host:
        return NormalisedUrl(raw, raw, parts.scheme.lower(), "", "", "", parts.path, False, False, None,
                             parts.scheme.lower() in ("javascript", "data"), "no host")
    host_ascii = host
    try:
        decoded = host.encode("ascii").decode("idna") if "xn--" in host else host
    except Exception:
        decoded = host
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        if re.fullmatch(r"\d+", host) or re.fullmatch(r"0x[0-9a-f]+", host):
            is_ip = True  # decimal / hex encoded IPv4
    path = unquote(parts.path or "")
    norm = f"{parts.scheme.lower()}://{host}{':' + str(port) if port else ''}{parts.path or '/'}"
    if parts.query:
        norm += "?" + parts.query
    return NormalisedUrl(raw, norm[:2000], parts.scheme.lower(), decoded, host_ascii,
                         host if is_ip else registrable_domain(decoded), path, is_ip, "@" in (parts.netloc or ""),
                         port, True)


def looks_like_url_or_domain(text: str) -> str | None:
    """Return the domain if an anchor's visible label claims a URL/domain."""
    t = text.strip().lower()
    m = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?", t)
    if m and (t.startswith("http") or t.startswith("www.") or re.fullmatch(r"(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#]\S*)?", t)):
        return m.group(1)
    return None
