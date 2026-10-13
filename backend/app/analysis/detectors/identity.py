"""Identity, authentication, impersonation and thread-context checks (deterministic rules).

Uploaded Authentication-Results headers are attacker-controllable unless written by a trusted
authserv-id, so they are reported as "reported, unverified" and passing results never lower risk.
Missing headers are reported as unavailable, never as a pass.
"""
from __future__ import annotations

import re

from ...config import RULES_VERSION
from ...email_processing.normalizer import skeleton
from ...email_processing.urls import registrable_domain
from ..context import AnalysisContext

FREEMAIL = {"gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com", "outlook.com", "live.com",
            "aol.com", "icloud.com", "me.com", "gmx.com", "gmx.net", "mail.com", "proton.me", "protonmail.com",
            "yandex.com", "yandex.ru", "zoho.com", "rediffmail.com", "msn.com"}
# Frequently impersonated brands used for lookalike comparison (legitimate registrable domains).
BRAND_DOMAINS = {"paypal.com", "microsoft.com", "office.com", "outlook.com", "apple.com", "amazon.com", "google.com",
                 "docusign.com", "dropbox.com", "netflix.com", "linkedin.com", "facebook.com", "instagram.com",
                 "wellsfargo.com", "chase.com", "bankofamerica.com", "citibank.com", "hsbc.com", "dhl.com", "fedex.com",
                 "ups.com", "usps.com", "irs.gov", "adobe.com", "sharepoint.com", "office365.com", "zoom.us",
                 "salesforce.com", "okta.com", "github.com", "coinbase.com", "binance.com", "sbi.co.in", "hdfcbank.com",
                 "icicibank.com"}
EXEC_TITLES = re.compile(r"\b(ceo|cfo|coo|president|chairman|managing director|director of finance|finance director|"
                         r"chief executive|chief financial)\b", re.I)


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(domain: str, candidates: set[str]) -> str | None:
    """Return the legitimate domain that `domain` imitates (edit distance / confusable skeleton)."""
    d = registrable_domain(domain)
    if not d or d in candidates:
        return None
    d_label = d.split(".")[0]
    d_skel = skeleton(d)
    for cand in candidates:
        c_label = cand.split(".")[0]
        if len(c_label) < 4:
            continue
        if d_skel == skeleton(cand) or skeleton(d_label) == skeleton(c_label):
            return cand
        if len(d_label) >= 5 and _lev(d_label, c_label) == 1:
            return cand
        if len(d_label) >= 6 and _lev(d_label, c_label) == 2 and d_label[0] == c_label[0]:
            return cand
        # brand embedded with hyphen tricks: paypal-secure.com, microsoft-support.net
        if re.fullmatch(rf"{re.escape(c_label)}[-.](\w+)|(\w+)[-.]{re.escape(c_label)}", d_label):
            return cand
    return None


def parse_auth_results(values: list[str]) -> list[dict]:
    out = []
    for v in values:
        authserv = v.split(";", 1)[0].strip().lower()
        res = {"authserv_id": authserv[:120]}
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}\s*=\s*(\w+)", v, re.I)
            res[mech] = m.group(1).lower() if m else "none"
        out.append(res)
    return out


def run(ctx: AnalysisContext) -> None:
    c = ctx.collector
    pe = ctx.parsed
    org = set(ctx.org_domains)
    if not pe.headers_present and not pe.from_addr:
        c.add(category="identity.headers_unavailable", component="coverage", severity="info",
              title="Sender/header checks unavailable", observed_value="no header block supplied",
              source_location="input", method="rule", version=RULES_VERSION, confidence=0.0, status="unavailable",
              explanation="Pasted body only: From/Reply-To/authentication/thread checks did not run. Upload the .eml "
                          "for identity analysis. This is not a pass.")
        return

    from_dom = pe.from_domain
    from_reg = registrable_domain(from_dom) if from_dom else ""

    # Display name containing a different email address / domain
    disp = pe.from_display or ""
    m = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", disp)
    if m and registrable_domain(m.group(1).lower()) != from_reg:
        c.add(category="identity.display_name_address_spoof", component="identity", severity="high",
              title="Display name shows a different address", observed_value=f'"{disp}" <{pe.from_addr}>',
              source_location="header:From", method="rule", version=RULES_VERSION, confidence=0.7, status="observed",
              explanation=f"The display name contains an address at {m.group(1)} while the real sender domain is {from_dom}.")

    # Reply-To divergence
    if pe.reply_to_addr and pe.reply_to_addr != pe.from_addr:
        rt_reg = registrable_domain(pe.reply_to_domain)
        if rt_reg != from_reg:
            if pe.reply_to_domain in FREEMAIL and from_reg not in FREEMAIL:
                strength = 0.65   # corporate sender, replies diverted to a personal mailbox
            elif pe.reply_to_domain in FREEMAIL and from_reg in FREEMAIL:
                strength = 0.6    # replies diverted to a different personal mailbox provider
            else:
                strength = 0.5
            c.add(category="identity.reply_to_mismatch", component="identity", severity="medium" if strength < 0.6 else "high",
                  title="Reply-To domain differs from From domain",
                  observed_value=f"From: {pe.from_addr} | Reply-To: {pe.reply_to_addr}", source_location="header:Reply-To",
                  method="rule", version=RULES_VERSION, confidence=strength, status="observed",
                  explanation="Replies would go to a different organisation than the apparent sender. Observed fact; "
                              "impersonation is a possible (inferred) explanation, mailing lists are a benign one.")
    if pe.return_path_domain and from_reg and registrable_domain(pe.return_path_domain) != from_reg:
        c.add(category="identity.return_path_mismatch", component="identity", severity="low",
              title="Return-Path domain differs from From domain",
              observed_value=f"Return-Path domain: {pe.return_path_domain}", source_location="header:Return-Path",
              method="rule", version=RULES_VERSION, confidence=0.2, status="observed",
              explanation="Common for newsletters/ESPs; weak on its own.")

    # Lookalike sender domain vs org / brands / vendor profiles
    vendor_domains = {d for p in ctx.profiles for d in p.domains}
    if from_dom:
        target = lookalike_of(from_dom, org | vendor_domains | BRAND_DOMAINS)
        if target:
            c.add(category="identity.lookalike_sender_domain", component="identity", severity="high",
                  title="Sender domain resembles a trusted/brand domain",
                  observed_value=f"{from_dom} ≈ {target}", source_location="header:From", method="rule",
                  version=RULES_VERSION, confidence=0.85 if target in org | vendor_domains else 0.75, status="observed",
                  explanation="Edit-distance / confusable-skeleton match to a known legitimate domain.")
        # trusted domain used as a subdomain of an unrelated registrable domain (org.example.attacker.test)
        for d in sorted(org | vendor_domains | BRAND_DOMAINS):
            if from_reg != registrable_domain(d) and (from_dom.startswith(d + ".") or f".{d}." in f".{from_dom}"):
                c.add(category="identity.trusted_domain_as_subdomain", component="identity", severity="high",
                      title="Sender domain embeds a trusted domain as a subdomain",
                      observed_value=f"{from_dom} (registrable domain: {from_reg})", source_location="header:From",
                      method="rule", version=RULES_VERSION, confidence=0.7, status="observed",
                      explanation=f"'{d}' appears at the start of the sender domain, but mail actually comes from {from_reg}.")
                break
        if "xn--" in from_dom:
            c.add(category="identity.punycode_sender", component="identity", severity="medium",
                  title="Internationalised (punycode) sender domain", observed_value=from_dom, source_location="header:From",
                  method="rule", version=RULES_VERSION, confidence=0.45, status="observed",
                  explanation="Punycode domains can render as look-alikes of Latin domains.")

    # Profiles: VIP / vendor impersonation
    for p in ctx.profiles:
        name_hit = p.name and disp and skeleton(p.name) in skeleton(disp)
        addr_known = pe.from_addr in p.emails or registrable_domain(from_dom) in p.domains
        if name_hit and not addr_known:
            c.add(category=f"identity.{p.kind}_impersonation", component="identity", severity="high",
                  title=f"Display name matches {p.kind.upper()} profile '{p.name}' but address is not on record",
                  observed_value=f'"{disp}" <{pe.from_addr}> (known: {", ".join(p.emails[:2] + p.domains[:2])})',
                  source_location="header:From", method="rule", version=RULES_VERSION, confidence=0.75, status="observed",
                  explanation="Configured profile lists different addresses/domains for this name.",
                  tags=[f"profile:{p.id}"])
        elif addr_known and pe.reply_to_addr and pe.reply_to_addr not in p.emails and \
                registrable_domain(pe.reply_to_domain) not in p.domains:
            c.add(category="identity.profile_reply_to_unknown", component="identity", severity="high",
                  title=f"Known {p.kind} sender but Reply-To is not on record", observed_value=pe.reply_to_addr,
                  source_location="header:Reply-To", method="rule", version=RULES_VERSION, confidence=0.6,
                  status="observed", explanation="Thread or account hijack can keep the real From while diverting replies.",
                  tags=[f"profile:{p.id}"])
    if ctx.profiles and from_reg in vendor_domains and ctx.sender_history_count == 0:
        c.add(category="context.first_contact", component="context", severity="info", title="First retained message from this address",
              observed_value=pe.from_addr, source_location="header:From", method="rule", version=RULES_VERSION,
              confidence=0.15, status="observed", explanation="Only messages retained by this application are counted.")

    # Freemail sender presenting as executive
    if from_reg in FREEMAIL and (EXEC_TITLES.search(disp) or EXEC_TITLES.search((ctx.body_n.text if ctx.body_n else "")[-400:])):
        c.add(category="identity.freemail_executive", component="identity", severity="medium",
              title="Executive role claimed from a free-mail account", observed_value=f'"{disp}" <{pe.from_addr}>',
              source_location="header:From", method="rule", version=RULES_VERSION, confidence=0.45, status="observed",
              explanation="Executives rarely conduct company payments from personal free-mail accounts.")

    # Authentication results
    if not pe.headers_present:
        return
    auth = parse_auth_results(pe.auth_results)
    if not auth:
        c.add(category="auth.unavailable", component="coverage", severity="info", title="No Authentication-Results header",
              observed_value="SPF/DKIM/DMARC: unavailable", source_location="header:Authentication-Results", method="rule",
              version=RULES_VERSION, confidence=0.0, status="unavailable",
              explanation="Authentication status is unknown (not a pass). Check your gateway's results.")
    for i, a in enumerate(auth[:3]):
        trusted = a["authserv_id"] in ctx.trusted_authserv_ids
        fails = [k for k in ("spf", "dkim", "dmarc") if a[k] in ("fail", "softfail", "permerror")]
        label = "trusted" if trusted else "reported, unverified (authserv-id not configured as trusted)"
        if fails:
            c.add(category="auth.failure_reported", component="identity", severity="high" if trusted else "medium",
                  title=f"Authentication failure {'verified' if trusted else 'reported'}: {', '.join(fails)}",
                  observed_value=f"{a['authserv_id']}: spf={a['spf']} dkim={a['dkim']} dmarc={a['dmarc']}",
                  source_location=f"header:Authentication-Results[{i}]", method="rule", version=RULES_VERSION,
                  confidence=0.6 if trusted else 0.35, status="observed", explanation=f"Source: {label}.")
        else:
            c.add(category="auth.status", component="coverage", severity="info",
                  title=f"Authentication results {label}",
                  observed_value=f"{a['authserv_id']}: spf={a['spf']} dkim={a['dkim']} dmarc={a['dmarc']}",
                  source_location=f"header:Authentication-Results[{i}]", method="rule", version=RULES_VERSION,
                  confidence=0.0, status="observed" if trusted else "unavailable",
                  explanation="A pass shows the domain authorised the message; it does not show the content is benign. "
                              "It never lowers the risk score.")

    # Thread consistency
    subj = pe.subject or ""
    if re.match(r"^\s*(re|fw|fwd|aw|sv)\s*:", subj, re.I) and not pe.in_reply_to and not pe.references:
        c.add(category="context.reply_without_thread", component="context", severity="low",
              title="Reply/forward subject without thread headers", observed_value=subj[:200], source_location="header:Subject",
              method="rule", version=RULES_VERSION, confidence=0.3, status="observed",
              explanation="Subject claims an existing conversation but In-Reply-To/References are absent. Some clients "
                          "strip these, so this is contextual evidence only.")
    body = ctx.body_n.text if ctx.body_n else ""
    quote = re.search(r"(^>.*$|^On .{5,80} wrote:$|^-{2,}\s*Original Message\s*-{2,}$|^From: .+$)", body, re.M | re.I)
    if quote and ("change_bank_details" in ctx.actions or ctx.bank_refs):
        new_part = body[:quote.start()]
        if re.search(r"\b(bank|account|iban|remit|wire)\b", new_part, re.I):
            c.add(category="context.new_payment_details_in_thread", component="context", severity="medium",
                  title="New payment details introduced above quoted history", observed_value=new_part[:200].strip(),
                  source_location=f"body[0:{quote.start()}]", method="rule", version=RULES_VERSION, confidence=0.5,
                  status="observed", explanation="Thread-hijack BEC often inserts new bank details into an existing conversation.")
