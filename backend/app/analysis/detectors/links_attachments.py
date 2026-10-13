"""Static URL and attachment forensics. URLs are never fetched; attachments are never executed."""
from __future__ import annotations

import re

from ...config import RULES_VERSION
from ...email_processing.urls import (ABUSED_TLDS, URL_SHORTENERS, looks_like_url_or_domain, normalise_url,
                                      registrable_domain)
from ..context import AnalysisContext
from .identity import BRAND_DOMAINS, lookalike_of

EXECUTABLE_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "hta",
                  "msi", "jar", "lnk", "cpl", "reg", "dll", "apk", "app", "dmg", "sh"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "iso", "img", "vhd", "cab", "ace"}
HTML_EXT = {"htm", "html", "shtml", "xhtml", "svg"}
EXT_TO_TYPES = {"pdf": {"application/pdf"}, "zip": {"application/zip"}, "docx": {"application/zip"},
                "xlsx": {"application/zip"}, "pptx": {"application/zip"}, "doc": {"application/x-ole-storage"},
                "xls": {"application/x-ole-storage"}, "ppt": {"application/x-ole-storage"}, "msg": {"application/x-ole-storage"},
                "png": {"image/png"}, "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"}, "gif": {"image/gif"},
                "txt": {"text/plain"}, "csv": {"text/plain"}, "html": {"text/html"}, "htm": {"text/html"},
                "rtf": {"application/rtf"}, "rar": {"application/x-rar"}, "7z": {"application/x-7z-compressed"},
                "iso": {"application/x-iso9660-image", "application/octet-stream"}}
LOGIN_WORDS = re.compile(r"(login|log-in|signin|sign-in|verify|account|secure|update|password|webscr|auth|wallet|banking)", re.I)


def run_urls(ctx: AnalysisContext) -> None:
    c = ctx.collector
    pe = ctx.parsed
    org = set(ctx.org_domains) | {d for p in ctx.profiles for d in p.domains}
    ctx.extra["normalised_urls"] = []
    for i, ref in enumerate(pe.urls):
        n = normalise_url(ref.url)
        ctx.extra["normalised_urls"].append(n)
        loc = f"url[{i}] {ref.source_location}"
        if not n.valid:
            c.add(category="url.malformed", component="url", severity="low", title="Malformed URL",
                  observed_value=ref.url[:200], source_location=loc, method="rule", version=RULES_VERSION,
                  confidence=0.25, status="observed", explanation=n.error or "could not parse")
            continue
        if n.scheme in ("javascript", "data", "vbscript"):
            c.add(category="url.active_scheme", component="url", severity="high", title=f"Active-content URL scheme ({n.scheme}:)",
                  observed_value=ref.url[:120], source_location=loc, method="rule", version=RULES_VERSION,
                  confidence=0.7, status="observed", explanation="Script/data URLs in mail are a strong evasion signal.")
            continue
        claimed = looks_like_url_or_domain(ref.anchor_text) if ref.anchor_text else None
        if claimed and registrable_domain(claimed) != n.registrable_domain:
            c.add(category="url.anchor_mismatch", component="url", severity="high",
                  title="Link text shows a different domain than the real target",
                  observed_value=f'text "{ref.anchor_text[:80]}" → {n.host}', source_location=loc, method="rule",
                  version=RULES_VERSION, confidence=0.75, status="observed",
                  explanation=f"Visible label points to {claimed} but the link opens {n.host}.")
        if n.is_ip:
            c.add(category="url.ip_literal", component="url", severity="medium", title="URL uses a raw IP address",
                  observed_value=n.host, source_location=loc, method="rule", version=RULES_VERSION, confidence=0.6,
                  status="observed", explanation="Legitimate organisations rarely link to bare IP addresses.")
        if n.has_userinfo:
            c.add(category="url.userinfo", component="url", severity="high", title="URL contains '@' userinfo trick",
                  observed_value=ref.url[:160], source_location=loc, method="rule", version=RULES_VERSION,
                  confidence=0.6, status="observed", explanation="Text before '@' is ignored by browsers and can imitate a trusted host.")
        if "xn--" in n.host_ascii:
            c.add(category="url.punycode", component="url", severity="medium", title="Punycode (IDN) host",
                  observed_value=f"{n.host_ascii} → {n.host}", source_location=loc, method="rule", version=RULES_VERSION,
                  confidence=0.5, status="observed", explanation="IDN hosts can visually imitate Latin domains.")
        if not n.is_ip:
            target = lookalike_of(n.host, org | BRAND_DOMAINS)
            if target:
                c.add(category="url.lookalike_domain", component="url", severity="high", title="Link domain resembles a known domain",
                      observed_value=f"{n.registrable_domain} ≈ {target}", source_location=loc, method="rule",
                      version=RULES_VERSION, confidence=0.8, status="observed",
                      explanation="Edit-distance / confusable-skeleton / hyphenated-brand match.")
            else:
                sub = n.host[: -len(n.registrable_domain)] if n.host.endswith(n.registrable_domain) else ""
                for b in BRAND_DOMAINS | org:
                    lab = b.split(".")[0]
                    if len(lab) >= 4 and n.registrable_domain != b and (lab in sub or lab in n.path.lower()[:120]):
                        c.add(category="url.brand_in_subdomain_or_path", component="url", severity="medium",
                              title="Brand name used outside its own domain",
                              observed_value=f"{lab} in {n.host}{n.path[:60]}", source_location=loc, method="rule",
                              version=RULES_VERSION, confidence=0.55, status="observed",
                              explanation=f"'{lab}' appears in the subdomain/path but the registrable domain is {n.registrable_domain}.")
                        break
            if n.registrable_domain in URL_SHORTENERS:
                c.add(category="url.shortener", component="url", severity="low", title="URL shortener hides the destination",
                      observed_value=n.host, source_location=loc, method="rule", version=RULES_VERSION, confidence=0.3,
                      status="observed", explanation="Destination cannot be checked statically (no URL is fetched).")
            tld = n.host.rsplit(".", 1)[-1]
            if tld in ABUSED_TLDS:
                c.add(category="url.abused_tld", component="url", severity="low", title=f"Frequently abused TLD .{tld}",
                      observed_value=n.host, source_location=loc, method="rule", version=RULES_VERSION, confidence=0.2,
                      status="observed", explanation="Weak signal; many legitimate sites use these TLDs.")
            if n.host.count(".") >= 4:
                c.add(category="url.deep_subdomains", component="url", severity="low", title="Unusually deep subdomain chain",
                      observed_value=n.host, source_location=loc, method="rule", version=RULES_VERSION, confidence=0.25,
                      status="observed", explanation="Long subdomain chains are used to push the real domain out of view.")
        if n.scheme == "http" and LOGIN_WORDS.search(n.path + n.host):
            c.add(category="url.plain_http_login", component="url", severity="low", title="Unencrypted link to a login-like page",
                  observed_value=ref.url[:160], source_location=loc, method="rule", version=RULES_VERSION, confidence=0.3,
                  status="observed", explanation="Credential pages served over HTTP are unusual for legitimate services.")
        if len(ref.url) > 180 or re.search(r"%[0-9a-f]{2}.*%[0-9a-f]{2}.*%[0-9a-f]{2}", n.host_ascii, re.I):
            c.add(category="url.obfuscated", component="url", severity="low", title="Very long or encoded URL",
                  observed_value=ref.url[:160] + ("…" if len(ref.url) > 160 else ""), source_location=loc, method="rule",
                  version=RULES_VERSION, confidence=0.15, status="observed", explanation="Weak obfuscation signal.")
    if pe.html:
        for j, form in enumerate(pe.html.forms):
            if form["has_password"]:
                c.add(category="url.embedded_credential_form", component="url", severity="high",
                      title="HTML form with a password field inside the email", observed_value=f"action={form['action'][:120]}",
                      source_location=f"html:form[{j}]", method="rule", version=RULES_VERSION, confidence=0.7,
                      status="observed", explanation="Legitimate services do not collect passwords in email bodies.")
        if pe.html.scripts_present:
            c.add(category="url.script_in_html", component="url", severity="medium", title="<script> element in HTML body",
                  observed_value=f"{pe.html.scripts_present} script element(s) (not executed)", source_location="html",
                  method="rule", version=RULES_VERSION, confidence=0.4, status="observed",
                  explanation="Mail clients block scripts; their presence suggests crafted content.")
    if pe.urls:
        c.add(category="url.page_analysis", component="coverage", severity="info", title="Live page analysis unavailable",
              observed_value=f"{len(pe.urls)} URL(s) analysed statically", source_location="urls", method="rule",
              version=RULES_VERSION, confidence=0.0, status="unavailable",
              explanation="No isolated renderer is configured, so linked pages were not visited (by design, to prevent SSRF).")


def run_attachments(ctx: AnalysisContext) -> None:
    c = ctx.collector
    for a in ctx.parsed.attachments:
        loc = a.location
        name = a.filename.lower()
        parts = name.split(".")
        if a.extension in EXECUTABLE_EXT:
            c.add(category="attachment.executable", component="attachment", severity="critical",
                  title=f"Executable/script attachment (.{a.extension})", observed_value=a.filename, source_location=loc,
                  method="rule", version=RULES_VERSION, confidence=0.85, status="observed",
                  explanation="Executable content is the classic malware delivery vector. It was not opened.")
        if len(parts) >= 3 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"} and \
                (parts[-1] in EXECUTABLE_EXT | ARCHIVE_EXT | HTML_EXT):
            c.add(category="attachment.double_extension", component="attachment", severity="high",
                  title="Double file extension", observed_value=a.filename, source_location=loc, method="rule",
                  version=RULES_VERSION, confidence=0.8, status="observed",
                  explanation="A benign-looking extension precedes the real one to disguise the file type.")
        if a.extension in MACRO_EXT:
            c.add(category="attachment.macro_document", component="attachment", severity="medium",
                  title="Macro-enabled Office document", observed_value=a.filename, source_location=loc, method="rule",
                  version=RULES_VERSION, confidence=0.55, status="observed", explanation="Macros were not inspected or run.")
        if a.extension in HTML_EXT or a.detected_type == "text/html":
            c.add(category="attachment.html", component="attachment", severity="medium",
                  title="HTML attachment", observed_value=a.filename, source_location=loc, method="rule",
                  version=RULES_VERSION, confidence=0.55, status="observed",
                  explanation="Local HTML files are used to host credential-harvesting forms offline.")
        if a.extension in ARCHIVE_EXT:
            c.add(category="attachment.archive", component="attachment", severity="low", title="Archive/disk-image attachment",
                  observed_value=a.filename, source_location=loc, method="rule", version=RULES_VERSION, confidence=0.3,
                  status="observed", explanation="Archives were not unpacked (decompression is out of scope by design).")
        expected = EXT_TO_TYPES.get(a.extension)
        if expected and a.detected_type not in expected and a.detected_type not in ("text/plain", "application/octet-stream"):
            c.add(category="attachment.type_mismatch", component="attachment", severity="high",
                  title="File content does not match its extension",
                  observed_value=f"{a.filename}: extension .{a.extension}, magic bytes → {a.detected_type}",
                  source_location=loc, method="rule", version=RULES_VERSION, confidence=0.7, status="observed",
                  explanation="Signature (magic bytes) disagrees with the declared extension.")
        if a.detected_type == "application/x-dosexec" and a.extension not in EXECUTABLE_EXT:
            c.add(category="attachment.hidden_executable", component="attachment", severity="critical",
                  title="Windows executable disguised by extension", observed_value=a.filename, source_location=loc,
                  method="rule", version=RULES_VERSION, confidence=0.9, status="observed",
                  explanation="File begins with the 'MZ' executable header.")
        if a.text_extraction_status != "extracted":
            c.add(category="attachment.content_unavailable", component="coverage", severity="info",
                  title="Attachment content not inspected", observed_value=f"{a.filename} ({a.text_extraction_status})",
                  source_location=loc, method="rule", version=RULES_VERSION, confidence=0.0, status="unavailable",
                  explanation="Only plain-text/HTML attachments are text-extracted; OCR/QR/PDF parsing is not enabled.")
