"""Model C — tactic and requested-action extraction (documented local rules).

No labelled tactic dataset is available, so these are transparent lexical/contextual rules
with source-linked spans — not a trained multi-label model. Each match records the field,
offsets and excerpt. Tactics alone are weak; requested high-impact actions are what raise risk.
"""
from __future__ import annotations

import re

from ...config import RULES_VERSION
from ..context import AnalysisContext
from ..evidence import excerpt

F = re.I

TACTICS: dict[str, list[re.Pattern]] = {
    "urgency": [re.compile(p, F) for p in [
        r"\b(urgent(ly)?|immediately|asap|right away|as soon as possible|time[- ]sensitive|without delay|act now|"
        r"don'?t delay|final (notice|warning|reminder)|last chance)\b",
        r"\bwithin (the next )?(\d{1,2}|twenty[- ]four|forty[- ]eight|one|two) (hours?|hrs?|minutes?)\b",
        r"\b(by|before) (the )?(end|close) of (the )?(day|business)\b|\b(by|before) (noon|cob|eod)\b",
        r"\b(expires?|expiring|will expire|deadline) (today|tonight|soon|in \d+)\b",
    ]],
    "authority": [re.compile(p, F) for p in [
        r"\b(ceo|cfo|coo|cto|chief (executive|financial|operating) officer|managing director|company president|"
        r"chairman|head of (finance|accounts|it|security)|finance director)\b",
        r"\b(it (department|support|helpdesk|service desk|team)|help ?desk|system administrator|security team|"
        r"compliance (team|department)|legal department|payroll department|hr department)\b",
        r"\b(irs|hmrc|tax authorit(y|ies)|federal agency|police|court order|law enforcement)\b",
        r"\bon behalf of (the )?(ceo|cfo|management|board|director)\b",
    ]],
    "fear": [re.compile(p, F) for p in [
        r"\b(suspend(ed|sion)?|deactivat(e|ed|ion)|terminat(e|ed|ion)|locked( out)?|frozen|blocked)\b.{0,40}\b(account|access|mailbox|card|service)\b",
        r"\b(account|access|mailbox|card|service)\b.{0,40}\b(suspend(ed)?|deactivat(ed)?|terminat(ed)?|locked|frozen|disabled|closed|deleted)\b",
        r"\bunauthori[sz]ed (access|activity|login|sign[- ]in|transaction|charge)s?\b",
        r"\b(security (alert|breach|incident|warning)|unusual (sign[- ]in|activity|login)|has been compromised)\b",
        r"\b(legal action|penalt(y|ies)|lawsuit|arrest warrant|will be (prosecuted|fined))\b",
    ]],
    "secrecy": [re.compile(p, F) for p in [
        r"\bkeep (this|it|the matter) (between us|private|quiet|confidential|discreet)\b",
        r"\b(do not|don'?t|please don'?t) (discuss|share|tell|mention|inform|copy|cc|loop in)\b.{0,40}\b(anyone|others|colleagues|team|finance|management|him|her)\b",
        r"\b(strictly|highly) (private|confidential)\b|\bdiscreet(ly)?\b|\bbetween (you and me|us)\b",
        r"\b(confidential (matter|acquisition|transaction|project|deal))\b",
    ]],
    "scarcity_reward": [re.compile(p, F) for p in [
        r"\byou('ve| have) (won|been selected|been chosen)\b|\b(winner|lottery|jackpot|inheritance)\b",
        r"\b(claim your|collect your) (prize|reward|refund|gift|funds)\b",
        r"\b(limited (time|offer|slots?)|exclusive (offer|deal)|only \d+ (left|remaining))\b",
        r"\b(refund|compensation|bonus) (of|is) (pending|due|available|approved)\b",
    ]],
    "familiarity_trust": [re.compile(p, F) for p in [
        r"\b(as (we )?discussed|per our (conversation|call|discussion|meeting)|as promised|following our (call|meeting))\b",
        r"\b(our (long[- ]standing|valued) (partnership|relationship)|trusted (partner|vendor|supplier))\b",
    ]],
    "policy_bypass": [re.compile(p, F) for p in [
        r"\b(bypass|skip|waive)\b.{0,30}\b(approval|process|procedure|verification|policy|controls?)\b",
        r"\bwithout (the )?(usual|normal|standard|second) (approval|sign[- ]off|process|verification|check)\b",
        r"\bno need to (verify|check|call|confirm|involve)\b|\b(do not|don'?t) (call|phone) (me|to confirm|to verify)\b",
        r"\b(i('m| am) (in a meeting|travel+ing|on a flight|unavailable|in meetings all day)|can'?t (talk|take calls?))\b",
        r"\b(only|just) (reach|contact|email) me (by|via|on|at) (email|this address|my personal)\b",
    ]],
    "credential_harvesting": [re.compile(p, F) for p in [
        r"\b(verify|confirm|validate|update|re-?enter|re-?activate|restore|unlock)\b.{0,25}\b(your )?(account|identity|password|credentials|login|log-?in details|sign-?in|mailbox|email account)\b",
        r"\b(enter|provide|submit|type)\b.{0,20}\b(your )?(password|passcode|credentials|pin|username and password)\b",
        r"\b(password|mailbox|account)\b.{0,20}\b(expire[sd]?|expiring|expiry|quota|storage (is )?full|full)\b",
        r"\b(sign|log)[- ]?in (here|below|now|to (verify|confirm|restore|avoid|keep|continue))\b",
    ]],
    "financial_diversion": [re.compile(p, F) for p in [
        r"\b(change|changed|update|updated|new)\b.{0,30}\b(bank(ing)?|account|payment|remittance|wire)\b.{0,15}\b(details|information|instructions|account|info)\b",
        r"\b(wire transfer|bank transfer|iban|swift( code)?|routing number|sort code|beneficiary)\b",
        r"\b(direct deposit|payroll|salary)\b.{0,40}\b(change|update|new account|switch)\b|\b(change|update|switch)\b.{0,40}\b(direct deposit|payroll|salary)\b",
        r"\b(gift ?cards?|itunes cards?|google play cards?|steam cards?|bitcoin|btc|crypto(currency)? wallet)\b",
        r"\b(outstanding|overdue|unpaid|pending) (invoice|payment|balance)s?\b|\b(process|make|release|send) (the |a |this )?(payment|wire|transfer)\b",
    ]],
}

HIGH_IMPACT_ACTIONS = {"provide_credentials", "provide_mfa_code", "change_bank_details", "payroll_change", "buy_gift_cards",
                       "disclose_sensitive_data", "manipulate_ai_assistant"}
ACTIONS: dict[str, list[re.Pattern]] = {
    "provide_credentials": [re.compile(p, F) for p in [
        r"\b(verify|confirm|validate|update|re-?enter|enter|provide|submit)\b.{0,25}\b(your )?(password|credentials|login details|log-?in|sign-?in details|username)\b",
        r"\b(sign|log)[- ]?in\b.{0,40}\b(verify|confirm|restore|avoid|keep|unlock|reactivate)\b",
        r"\b(sign|log)[- ]?in\b.{0,25}\bto (view|access|open|download|see|read)\b",
        r"\b(verify|confirm|validate)\b.{0,15}\b(your )?(account|identity|mailbox|email account)\b",
    ]],
    "provide_mfa_code": [re.compile(p, F) for p in [
        r"\b(send|share|provide|forward|reply with|read (out|back)|tell me|give me)\b.{0,40}\b(verification code|one[- ]time (code|password|passcode|pin)|otp|mfa code|2fa code|authenticat(ion|or) code|security code|6[- ]digit code)\b",
        r"\b(verification code|one[- ]time (code|password|passcode)|otp|mfa code|2fa code|authenticator code)\b.{0,40}\b(send|share|provide|reply|forward|text)\b",
    ]],
    "change_bank_details": [re.compile(p, F) for p in [
        r"\b(change|changed|update|updated|new|different)\b.{0,30}\b(bank(ing)?|account|remittance|payment|wire)\b.{0,15}\b(details|information|instructions|account|info)\b",
        r"\b(send|make|direct|route|wire|remit|transfer|pay)\b.{0,40}\b(to|into) (our|the|this|a) (new|updated|alternative|different) (bank )?account\b",
        r"\bdo not (pay|send|remit)\b.{0,40}\b(old|previous|existing|usual) (account|bank|details)\b",
    ]],
    "payment_request": [re.compile(p, F) for p in [
        r"\b(process|make|release|send|initiate|arrange|complete|pay)\b.{0,25}\b(the |a |this |an |urgent )?(payment|wire|transfer|invoice)\b",
        r"\b(wire|transfer|remit|pay)\b.{0,15}\b(\$|usd|eur|€|£|gbp|inr|₹)\s?\d",
    ]],
    "payroll_change": [re.compile(p, F) for p in [
        r"\b(change|update|switch)\b.{0,40}\b(direct deposit|payroll|salary)\b",
        r"\b(direct deposit|payroll|salary)\b.{0,40}\b(change|update|new account|new bank)\b",
    ]],
    "buy_gift_cards": [re.compile(p, F) for p in [
        r"\b(buy|purchase|get|pick up|send me)\b.{0,40}\b(gift ?cards?|itunes cards?|google play cards?|steam cards?|vouchers?)\b",
        r"\b(scratch|send)\b.{0,30}\b(the )?(codes?|card numbers?)\b.{0,30}\b(cards?)\b",
    ]],
    "open_attachment": [re.compile(p, F) for p in [
        r"\b(open|review|see|download|view|check|sign)\b.{0,20}\b(the )?(attached|attachment|enclosed|document|file|invoice|pdf|statement)\b",
    ]],
    "click_link": [re.compile(p, F) for p in [
        r"\b(click|tap|press)\b.{0,15}\b(here|the link|below|on the link|this link|the button)\b",
        r"\b(follow|visit|use|open)\b.{0,10}\b(the|this) (link|url|portal|page)\b",
    ]],
    "disclose_sensitive_data": [re.compile(p, F) for p in [
        r"\b(send|share|provide|forward|email)\b.{0,30}\b(w-?2s?|tax forms?|employee (list|records|data|details)|customer (list|data|records)|"
        r"ssn|social security|passport|personal (information|details)|confidential (files|documents|data)|client list)\b",
    ]],
    "call_number": [re.compile(p, F) for p in [
        r"\b(call|phone|ring|dial|contact)\b.{0,40}\b(at|on|number|line|toll[- ]free|helpline|support)\b.{0,25}\+?\(?\d[\d\s().-]{6,}\d",
        r"\+?\(?\d[\d\s().-]{6,}\d.{0,40}\b(call (us|now|immediately|today)|to (cancel|dispute|stop))\b",
    ]],
    "reply_new_recipient": [re.compile(p, F) for p in [
        r"\b(reply|respond|send (it|them|your (reply|response|confirmation)))\b.{0,20}\b(directly )?to\b.{0,10}[\w.+-]+@[\w-]+\.[\w.]+",
        r"\b(use|contact me (at|on)|email me (at|on))\b.{0,15}\b(my )?(personal|private|new|alternate|other) (email|address|number)\b",
    ]],
}

_PHONE = re.compile(r"(?<![\w.])\+?\(?\d{1,4}\)?[\s.-]?\(?\d{2,4}\)?[\s.-]\d{3,4}[\s.-]?\d{2,4}(?![\w])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b")
_ACCT = re.compile(r"\b(?:account|acct|a/c)(?: number| no\.?|#)?[:\s]+(\d[\d\s-]{6,20}\d)\b", re.I)


def run(ctx: AnalysisContext) -> None:
    c = ctx.collector
    for tactic, patterns in TACTICS.items():
        for field, nt in ctx.fields:
            for rx in patterns:
                m = rx.search(nt.text)
                if not m:
                    continue
                s, e = nt.to_original(m.start(), m.end())
                f = c.add(category=f"tactic.{tactic}", component="intent", severity="low",
                          title=f"Social-engineering tactic: {tactic.replace('_', ' ')}",
                          observed_value=excerpt(nt.original, s, e), source_location=f"{field}[{s}:{e}]",
                          method="rule", version=RULES_VERSION, confidence=0.35, status="observed",
                          explanation=f"Phrase matching the '{tactic}' lexicon rule. A tactic on its own is weak evidence; "
                                      "legitimate mail also uses urgency or authority language.",
                          span={"field": field, "start": s, "end": e}, tags=[tactic])
                ctx.tactics.setdefault(tactic, []).append(f.finding_id)
                break  # one finding per tactic per field
    for action, patterns in ACTIONS.items():
        for field, nt in ctx.fields:
            hit = None
            for rx in patterns:
                hit = rx.search(nt.text)
                if hit:
                    break
            if not hit:
                continue
            s, e = nt.to_original(hit.start(), hit.end())
            high = action in HIGH_IMPACT_ACTIONS
            f = c.add(category=f"action.{action}", component="intent", severity="high" if high else "medium",
                      title=f"Requested action: {action.replace('_', ' ')}",
                      observed_value=excerpt(nt.original, s, e), source_location=f"{field}[{s}:{e}]",
                      method="rule", version=RULES_VERSION, confidence=0.6 if high else 0.3, status="observed",
                      explanation=("High-impact request: if fraudulent it leads directly to credential or financial loss."
                                   if high else "Common in both legitimate and malicious mail; weighs in only with other evidence."),
                      span={"field": field, "start": s, "end": e}, tags=[action])
            ctx.actions.setdefault(action, []).append(f.finding_id)
            break
    body = ctx.body_n.text if ctx.body_n else ""
    ctx.phones = sorted({re.sub(r"[^\d+]", "", m.group(0)) for m in _PHONE.finditer(body)
                         if 9 <= len(re.sub(r"\D", "", m.group(0))) <= 15})[:10]
    refs = [m.group(0).replace(" ", "") for m in _IBAN.finditer(ctx.body_n.original if ctx.body_n else "")]
    refs += [re.sub(r"\D", "", m.group(1)) for m in _ACCT.finditer(body)]
    ctx.bank_refs = sorted(set(refs))[:10]
    for ref in ctx.bank_refs:
        idx = (ctx.body_n.original if ctx.body_n else "").replace(" ", "").find(ref)
        c.add(category="indicator.bank_reference", component="context", severity="info",
              title="Bank account reference in message", observed_value=f"…{ref[-4:]} (masked)",
              source_location="body", method="rule", version=RULES_VERSION, confidence=0.1, status="observed",
              explanation="Account identifiers are stored masked/hashed and used for campaign correlation.", tags=["bank_ref"])

    # Callback lure: call action + pressure tactic (urgency/fear/authority) on a number in the body
    if "call_number" in ctx.actions and ({"urgency", "fear"} & set(ctx.tactics)):
        c.add(category="action.callback_lure", component="intent", severity="medium",
              title="Possible callback (telephone-oriented) lure",
              observed_value=", ".join(ctx.phones[:3]) or "phone number in body", source_location="body",
              method="rule", version=RULES_VERSION, confidence=0.5, status="inferred",
              explanation="Instruction to call a number combined with urgency/fear. Verify the number against an "
                          "independently known contact for the organisation.",
              tags=["call_number"], related=ctx.actions["call_number"])

    # Zero-link BEC: financial/credential request + pressure tactics with no URL or attachment
    fin = {"change_bank_details", "payroll_change", "buy_gift_cards", "payment_request", "provide_mfa_code",
           "disclose_sensitive_data"} & set(ctx.actions)
    pressure = {"urgency", "secrecy", "authority", "policy_bypass", "fear"} & set(ctx.tactics)
    if fin and pressure and not ctx.parsed.urls and not ctx.parsed.attachments:
        ids = [i for a in fin for i in ctx.actions[a]] + [i for t in pressure for i in ctx.tactics[t]]
        c.add(category="intent.zero_link_bec", component="intent", severity="high",
              title="Zero-link BEC pattern", observed_value=f"actions: {', '.join(sorted(fin))}; tactics: {', '.join(sorted(pressure))}",
              source_location="body", method="rule", version=RULES_VERSION,
              confidence=0.7 if len(pressure) >= 2 else 0.55, status="inferred",
              explanation="A financial/data request combined with pressure tactics and no link or attachment is the "
                          "typical shape of business email compromise. This is an inference from the linked findings.",
              tags=["bec"], related=ids)
