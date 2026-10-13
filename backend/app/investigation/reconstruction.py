"""Signature 2 — evidence-linked attack reconstruction.

Builds  sender claim → observed signals → tactics → requested action → possible objective/impact
from real findings only. Every node and edge lists the finding ids that support it; nodes that
are interpretations are marked "inferred". When the findings do not support a story the output
says "insufficient evidence" instead of inventing one.
"""
from __future__ import annotations

from ..analysis.evidence import Finding
from ..analysis.fusion import WEIGHTS

OBJECTIVES = {
    "provide_credentials": ("Credential theft / account takeover", "Attacker could sign in as the recipient."),
    "provide_mfa_code": ("MFA bypass / account takeover", "A shared one-time code can complete an attacker's sign-in."),
    "change_bank_details": ("Payment diversion (BEC)", "Future payments could be sent to an attacker-controlled account."),
    "payment_request": ("Fraudulent payment", "Funds could be transferred on a fraudulent instruction."),
    "payroll_change": ("Payroll diversion", "An employee's salary could be redirected."),
    "buy_gift_cards": ("Gift-card fraud", "Untraceable value could be extracted."),
    "disclose_sensitive_data": ("Data theft", "Personal or confidential data could be exposed."),
    "open_attachment": ("Possible malware delivery", "Opening the file could run attacker code (file was not executed here)."),
    "click_link": ("Redirect to an external page", "The linked page could harvest credentials or deliver malware (not visited)."),
    "call_number": ("Telephone-oriented fraud", "A phone call moves the victim to a channel without email controls."),
    "reply_new_recipient": ("Conversation diversion", "Replies would reach a party other than the apparent sender."),
    "manipulate_ai_assistant": ("Manipulate an AI email assistant", "An assistant could leak data or misreport the email."),
}
SIGNAL_COMPONENTS = ("identity", "url", "attachment", "evasion", "context", "reputation", "ai_injection")

VERIFY = [
    (("identity.reply_to_mismatch", "identity.vip_impersonation", "identity.vendor_impersonation", "identity.lookalike_sender_domain",
      "identity.display_name_address_spoof", "identity.freemail_executive", "identity.profile_reply_to_unknown"),
     "Confirm the sender through a contact channel you already know (directory, vendor master file) — not one given in "
     "this email. Confirmation would resolve the identity concern; the request itself should still follow normal approval."),
    (("action.change_bank_details", "action.payroll_change", "intent.zero_link_bec", "context.new_payment_details_in_thread"),
     "Before any payment or bank-detail change, call the requester on a previously known number and require a second approver."),
    (("action.provide_credentials", "url.embedded_credential_form", "tactic.credential_harvesting"),
     "Do not enter credentials from this email. Open the service by typing its address and check whether any alert actually exists."),
    (("action.provide_mfa_code",), "Never share one-time codes. A real service will not ask for them by email or phone."),
    (("auth.unavailable", "identity.headers_unavailable", "auth.status"),
     "Check SPF/DKIM/DMARC as recorded by your own mail gateway; results inside an uploaded file are not verified."),
    (("ai_injection.directive", "hidden.content"),
     "Do not let an AI assistant summarise or act on this email automatically; review the hidden content shown as evidence."),
    (("url.anchor_mismatch", "url.lookalike_domain", "url.brand_in_subdomain_or_path", "url.ip_literal", "url.userinfo", "url.punycode"),
     "Compare each link's real destination with the organisation's official domain before clicking."),
    (("attachment.executable", "attachment.double_extension", "attachment.type_mismatch", "attachment.hidden_executable",
      "attachment.macro_document", "attachment.html"),
     "Do not open the attachment on a workstation; if needed, analyse it in an approved sandbox."),
    (("action.callback_lure", "action.call_number"),
     "Look up the organisation's phone number independently instead of calling the number in the email."),
]

ATTACK = [
    ("T1566.002", "Phishing: Spearphishing Link", lambda cats, acts: any(c.startswith("url.") and c not in ("url.page_analysis",) for c in cats) and ("click_link" in acts or "provide_credentials" in acts)),
    ("T1566.001", "Phishing: Spearphishing Attachment", lambda cats, acts: any(c.startswith("attachment.") and c != "attachment.content_unavailable" for c in cats)),
    ("T1598", "Phishing for Information", lambda cats, acts: bool({"provide_credentials", "provide_mfa_code", "disclose_sensitive_data"} & acts)),
    ("T1656", "Impersonation", lambda cats, acts: any(c in cats for c in ("identity.vip_impersonation", "identity.vendor_impersonation",
                                                                            "identity.lookalike_sender_domain", "identity.display_name_address_spoof"))),
    ("T1566", "Phishing (no link/attachment sub-technique applies)", lambda cats, acts: "intent.zero_link_bec" in cats),
    ("AML.T0051", "MITRE ATLAS: LLM Prompt Injection (indirect)", lambda cats, acts: "ai_injection.directive" in cats and "manipulate_ai_assistant" in acts),
]


def build(findings: list[Finding], parsed_summary: dict, decision: dict, model_out: dict | None,
          actions: dict[str, list[str]], tactics: dict[str, list[str]], impact: dict) -> dict:
    fmap = {f.finding_id: f for f in findings}
    nodes: list[dict] = []
    edges: list[dict] = []

    def node(nid, kind, label, status, evidence, detail=""):
        nodes.append({"id": nid, "kind": kind, "label": label, "status": status, "evidence": evidence, "detail": detail})

    def edge(a, b, rel, evidence, status="observed"):
        edges.append({"source": a, "target": b, "relation": rel, "evidence": evidence, "status": status})

    # 1. sender claim
    if parsed_summary.get("from_addr"):
        claim = f'{parsed_summary.get("from_display") or ""} <{parsed_summary["from_addr"]}>'.strip()
        node("sender", "sender_claim", f"Claims to be: {claim}", "observed", [], "header:From")
    else:
        node("sender", "sender_claim", "Sender unknown (no headers supplied)", "unavailable", [], "input had no header block")

    # 2. observed signals
    sig = [f for f in findings if f.component in SIGNAL_COMPONENTS and f.status in ("observed", "inferred") and f.confidence >= 0.2]
    sig.sort(key=lambda f: -f.confidence)
    for f in sig[:12]:
        node(f"sig:{f.finding_id}", "signal", f.title, f.status, [f.finding_id], f.observed_value[:160])
        rel = "undermines sender claim" if f.component == "identity" else "observed in message"
        edge("sender", f"sig:{f.finding_id}", rel, [f.finding_id], f.status)
    if model_out:
        node("model", "signal", f"Text model score {model_out['score']:.2f} (threshold {model_out['threshold']:.2f})",
             "observed", [fid for fid, f in fmap.items() if f.component == "text_model"],
             ", ".join(c["feature"] for c in model_out.get("top_contributions", [])[:5] if c["contribution"] > 0))
        edge("sender", "model", "content scored by trained model", node_evidence(nodes, "model"))

    # 3. tactics
    for t, ids in tactics.items():
        node(f"tactic:{t}", "tactic", t.replace("_", " ").title(), "observed", ids, fmap[ids[0]].observed_value[:160])
        edge("sender", f"tactic:{t}", "uses tactic", ids)

    # 4. requested actions and 5. objectives
    for a, ids in actions.items():
        ids = [i for i in ids if i in fmap]
        if not ids:
            continue
        node(f"action:{a}", "requested_action", a.replace("_", " ").capitalize(), "observed", ids, fmap[ids[0]].observed_value[:160])
        for t, tids in tactics.items():
            # tactics and the request co-occur in the same message; the edge records co-occurrence, not causation
            edge(f"tactic:{t}", f"action:{a}", "co-occurs with request", tids + ids)
        if a in OBJECTIVES:
            obj, imp = OBJECTIVES[a]
            node(f"objective:{a}", "objective", f"Possible objective: {obj}", "inferred", ids, imp)
            edge(f"action:{a}", f"objective:{a}", "suggests (inference)", ids, "inferred")
    for f in sig[:12]:
        if f.component in ("url", "attachment"):
            target = "action:click_link" if f.component == "url" else "action:open_attachment"
            if any(n["id"] == target for n in nodes):
                edge(f"sig:{f.finding_id}", target, "delivery mechanism", [f.finding_id])

    has_story = bool(actions) or (bool(tactics) and decision["risk_score"] >= 35) or decision["verdict"] in ("LIKELY_PHISHING", "AI_INJECTION_SUSPECTED")
    timeline = _timeline(nodes, has_story, decision)
    cats = {f.category for f in findings if f.status in ("observed", "inferred")}
    acts = set(actions)
    verification = []
    for keys, text in VERIFY:
        ids = [f.finding_id for f in findings if f.category in keys]
        if ids:
            verification.append({"step": text, "resolves_uncertainty_in": ids})
    if model_out and abs(model_out["score"] - model_out["threshold"]) < 0.15:
        verification.append({"step": "The text model was uncertain; an analyst should read the full message in context.",
                             "resolves_uncertainty_in": [f.finding_id for f in findings if f.component == "text_model"]})
    attack = [{"id": tid, "name": name, "basis": "mapped from observed finding categories"}
              for tid, name, rule in ATTACK if rule(cats, acts)]
    if decision["verdict"] in ("NO_STRONG_INDICATORS", "INSUFFICIENT_EVIDENCE"):
        attack = []
    return {"nodes": nodes, "edges": edges, "timeline": timeline, "has_attack_story": has_story,
            "narrative": _narrative(nodes, has_story, decision, impact), "verification_steps": verification,
            "attack_mapping": attack,
            "caveat": "The system does not know the sender's real intent. Objectives are inferences from the linked "
                      "evidence; no attacker attribution is made."}


def node_evidence(nodes, nid):
    for n in nodes:
        if n["id"] == nid:
            return n["evidence"]
    return []


def _timeline(nodes, has_story, decision):
    order = ["sender_claim", "signal", "tactic", "requested_action", "objective"]
    titles = {"sender_claim": "1 · Sender identity claim", "signal": "2 · Observed signals", "tactic": "3 · Persuasion tactics",
              "requested_action": "4 · Requested action", "objective": "5 · Possible objective & impact"}
    steps = []
    for kind in order:
        items = [n for n in nodes if n["kind"] == kind]
        if not items:
            continue
        steps.append({"stage": titles[kind], "kind": kind,
                      "status": "inferred" if kind == "objective" else ("unavailable" if all(i["status"] == "unavailable" for i in items) else "observed"),
                      "items": [{"label": i["label"], "evidence": i["evidence"], "status": i["status"], "detail": i["detail"]} for i in items]})
    if not has_story:
        steps.append({"stage": "Assessment", "kind": "insufficient", "status": "observed",
                      "items": [{"label": "Insufficient evidence for an attack narrative", "evidence": [], "status": "observed",
                                 "detail": "No requested action or corroborated tactic was found; no story is constructed."}]})
    return steps


def _narrative(nodes, has_story, decision, impact) -> str:
    if not has_story:
        return ("Insufficient evidence for an attack narrative: the message contains no extracted requested action and "
                f"no corroborated persuasion pattern. Verdict: {decision['verdict_label']} (risk {decision['risk_score']}).")
    sender = next((n for n in nodes if n["kind"] == "sender_claim"), None)
    tactics = [n["label"].lower() for n in nodes if n["kind"] == "tactic"]
    actions = [n["label"].lower() for n in nodes if n["kind"] == "requested_action"]
    signals = [n for n in nodes if n["kind"] == "signal" and n["id"] != "model"]
    objs = [n["label"].replace("Possible objective: ", "") for n in nodes if n["kind"] == "objective"]
    parts = [f"The message {sender['label'].lower() if sender else 'has an unknown sender'}."]
    if signals:
        parts.append(f"{len(signals)} observed signal(s) were found, the strongest being: {signals[0]['label'].lower()} "
                     f"[{', '.join(signals[0]['evidence'])}].")
    if tactics:
        parts.append(f"It uses {', '.join(tactics)} language.")
    if actions:
        parts.append(f"It asks the recipient to: {', '.join(actions)}.")
    if objs:
        parts.append(f"If malicious, a possible objective is {', '.join(objs).lower()} (inference, not established fact).")
    parts.append(f"Potential impact is rated {impact['potential_impact']}; verdict: {decision['verdict_label']}.")
    return " ".join(parts)


def explanations(decision: dict, findings: list[Finding], strengths: dict, model_out: dict | None, unc: dict) -> dict:
    v = decision["verdict"]
    top = sorted([f for f in findings if f.status in ("observed", "inferred") and f.confidence >= 0.3], key=lambda f: -f.confidence)[:4]
    user = {
        "LIKELY_PHISHING": "This email shows several strong signs of a phishing or fraud attempt. Do not click links, open "
                           "attachments, pay, or reply with information. Report it to your security team.",
        "SUSPICIOUS_REVIEW": "Something about this email needs checking before you act on it. Verify the request through a "
                             "channel you already trust.",
        "AI_INJECTION_SUSPECTED": "This email contains hidden or embedded instructions aimed at AI assistants. Do not let an AI "
                                  "tool act on it; report it to your security team.",
        "NO_STRONG_INDICATORS": "No strong warning signs were found by the checks that ran. This is not a guarantee the email "
                                "is safe — stay cautious with unexpected requests.",
        "INSUFFICIENT_EVIDENCE": "There was not enough information to assess this email. Treat unexpected requests with caution.",
    }[v]
    if top:
        user += " Main reasons: " + "; ".join(f.title.lower() for f in top[:3]) + "."
    contrib = [{"group": g, "strength": strengths.get(g, 0), "weight": w}
               for g, w in WEIGHTS.items()]
    return {"user": user,
            "analyst": {"decision_reasons": decision["decision_reasons"], "group_strengths": contrib,
                        "top_findings": [f.finding_id for f in top], "uncertainty": unc,
                        "model_top_features": (model_out or {}).get("top_contributions", []),
                        "note": "Group strength = strongest finding + 15% of the second; content groups combined as "
                                "max + ½·min; other groups via weighted noisy-OR."}}
