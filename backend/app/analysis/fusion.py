"""Risk fusion and verdict policy (documented in docs/ARCHITECTURE.md §Risk fusion).

1. Each evidence group gets a strength s_g in [0,1]: the strongest finding in the group plus 15% of the
   second strongest (so many correlated findings in one group cannot stack up).
2. Content evidence (text model + intent rules) is correlated, so it is combined as
   max(a, b) + 0.5·min(a, b) of the weighted strengths instead of being treated as independent.
3. Remaining groups are combined with a weighted noisy-OR: risk = 1 − Π(1 − w_g·s_g).
4. The 0–100 result is a *policy risk score*, not a probability.
5. Verdict rules (in order) — see `decide`. Uncorroborated text-model evidence below the strong-score constant
   is reported as uncertainty instead of being routed to review (adopted after the dev-split run, see svm.md/IMPLEMENTATION_LOG). Thresholds below are policy constants chosen before the
   benchmark run; the text-model threshold itself was tuned on the validation split only.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import FUSION_VERSION
from .detectors.social_engineering import HIGH_IMPACT_ACTIONS
from .evidence import Finding

WEIGHTS = {"text_model": 0.55, "intent": 0.6, "identity": 0.55, "url": 0.55, "attachment": 0.65,
           "reputation": 0.95, "evasion": 0.35, "context": 0.35, "ai_injection": 0.7}
GROUPS = list(WEIGHTS)
DEFAULT_POLICY = {"likely_threshold": 65.0, "review_threshold": 35.0, "strong_group_strength": 0.6,
                  "strong_text_score": 0.85, "ai_injection_strength": 0.6, "reputation_malicious_strength": 0.9}

VERDICT_LABELS = {
    "LIKELY_PHISHING": "Likely phishing",
    "SUSPICIOUS_REVIEW": "Suspicious — review",
    "AI_INJECTION_SUSPECTED": "AI-assistant manipulation suspected",
    "NO_STRONG_INDICATORS": "No strong malicious indicators found",
    "INSUFFICIENT_EVIDENCE": "Insufficient evidence",
}


@dataclass
class FusionInput:
    strengths: dict[str, float]
    model_status: str                     # loaded|failed|missing|disabled
    model_score: float | None
    model_threshold: float
    high_impact_actions: list[str]
    identity_verified: bool
    word_count: int
    headers_present: bool
    parse_ok: bool
    language_supported: bool = True
    reputation_malicious: bool = False
    failed_stages: list[str] = field(default_factory=list)


def group_strengths(findings: list[Finding], model_score: float | None) -> dict[str, float]:
    by: dict[str, list[float]] = {g: [] for g in GROUPS}
    for f in findings:
        if f.status in ("observed", "inferred") and f.confidence > 0 and f.component in by:
            by[f.component].append(f.confidence)
    out = {}
    for g, vals in by.items():
        vals.sort(reverse=True)
        out[g] = round(min(1.0, (vals[0] + 0.15 * vals[1]) if len(vals) > 1 else (vals[0] if vals else 0.0)), 4)
    out["text_model"] = round(float(model_score), 4) if model_score is not None else 0.0
    return out


def risk_score(strengths: dict[str, float], disabled: set[str] | None = None) -> float:
    disabled = disabled or set()
    s = {g: (0.0 if g in disabled else strengths.get(g, 0.0)) for g in GROUPS}
    a = WEIGHTS["text_model"] * s["text_model"]
    b = WEIGHTS["intent"] * s["intent"]
    content = min(1.0, max(a, b) + 0.5 * min(a, b))
    remain = 1.0 - content
    for g in GROUPS:
        if g in ("text_model", "intent"):
            continue
        remain *= 1.0 - WEIGHTS[g] * s[g]
    return round(100.0 * (1.0 - remain), 1)


def decide(fi: FusionInput, policy: dict | None = None, disabled: set[str] | None = None) -> dict:
    p = {**DEFAULT_POLICY, **(policy or {})}
    disabled = disabled or set()
    st = {g: (0.0 if g in disabled else v) for g, v in fi.strengths.items()}
    score = risk_score(st)
    text_ok = fi.model_status == "loaded" and "text_model" not in disabled
    strong = [g for g in GROUPS if g not in ("text_model", "ai_injection") and st.get(g, 0) >= p["strong_group_strength"]]
    if text_ok and fi.model_score is not None and fi.model_score >= p["strong_text_score"]:
        strong.append("text_model")
    reasons: list[str] = []
    rule_signal = max((st.get(g, 0) for g in GROUPS if g != "text_model"), default=0.0)

    if not fi.parse_ok:
        verdict = "INSUFFICIENT_EVIDENCE"
        reasons.append("input could not be parsed")
    elif st.get("ai_injection", 0) >= p["ai_injection_strength"]:
        verdict = "AI_INJECTION_SUSPECTED"
        reasons.append("directive content aimed at an AI assistant")
    elif fi.reputation_malicious and st.get("reputation", 0) >= p["reputation_malicious_strength"]:
        verdict = "LIKELY_PHISHING"
        reasons.append("indicator listed as malicious by a reputation source")
    elif score >= p["likely_threshold"] and len(strong) >= 2:
        verdict = "LIKELY_PHISHING"
        reasons.append(f"risk {score} with {len(strong)} independent strong evidence groups ({', '.join(strong)})")
    elif score >= p["likely_threshold"]:
        verdict = "SUSPICIOUS_REVIEW"
        reasons.append(f"risk {score} but only one strong evidence group - single-source decisions go to review")
    elif (score >= p["review_threshold"] and text_ok and rule_signal < 0.3 and not fi.high_impact_actions
          and (fi.model_score or 0) < p["strong_text_score"]):
        verdict = "NO_STRONG_INDICATORS"
        reasons.append(f"only the text model leaned malicious (score {fi.model_score:.2f} < {p['strong_text_score']}) and no other "
                       "layer corroborated it; recorded as uncertainty rather than routed to review")
    elif score >= p["review_threshold"]:
        verdict = "SUSPICIOUS_REVIEW"
        reasons.append(f"risk {score} at or above review threshold {p['review_threshold']}")
    elif fi.high_impact_actions and not fi.identity_verified and "intent" not in disabled:
        verdict = "SUSPICIOUS_REVIEW"
        reasons.append(f"high-impact request ({', '.join(fi.high_impact_actions)}) with unverified sender identity")
    elif not text_ok and rule_signal < 0.3:
        verdict = "INSUFFICIENT_EVIDENCE"
        reasons.append("text model unavailable and no other layer produced meaningful evidence")
    elif fi.word_count < 8 and rule_signal < 0.3:
        verdict = "INSUFFICIENT_EVIDENCE"
        reasons.append(f"only {fi.word_count} words of content - too little to assess")
    elif not fi.language_supported and rule_signal < 0.3:
        verdict = "INSUFFICIENT_EVIDENCE"
        reasons.append("content appears to be outside the English-language coverage of the model and rules")
    else:
        verdict = "NO_STRONG_INDICATORS"
        reasons.append("no strong suspicious evidence among the layers that ran (not a safety guarantee)")
    flags = []
    if verdict == "AI_INJECTION_SUSPECTED" and score >= p["likely_threshold"] and len(strong) >= 2:
        flags.append("also_meets_likely_phishing_criteria")
    return {"verdict": verdict, "verdict_label": VERDICT_LABELS[verdict], "risk_score": score,
            "strong_groups": strong, "decision_reasons": reasons, "flags": flags, "policy": p,
            "fusion_version": FUSION_VERSION, "disabled_layers": sorted(disabled)}


def uncertainty(fi: FusionInput, decision: dict) -> dict:
    reasons = []
    if fi.model_status != "loaded":
        reasons.append("text model unavailable")
    elif fi.model_score is not None and abs(fi.model_score - fi.model_threshold) < 0.15:
        reasons.append(f"text model score {fi.model_score:.2f} is close to its decision threshold {fi.model_threshold:.2f}")
    rule_max = max((fi.strengths.get(g, 0) for g in GROUPS if g not in ("text_model",)), default=0)
    if fi.model_score is not None and fi.model_status == "loaded":
        if fi.model_score < fi.model_threshold and rule_max >= 0.6:
            reasons.append("conflict: text model leans benign but rule-based layers found strong evidence")
        if fi.model_score >= fi.model_threshold and rule_max < 0.3:
            reasons.append(f"text model leans malicious ({fi.model_score:.2f}) but no structural/identity/intent evidence corroborates it")
    if not fi.headers_present:
        reasons.append("no headers: identity, authentication and thread checks did not run")
    if fi.word_count < 20:
        reasons.append(f"short content ({fi.word_count} words)")
    if not fi.language_supported:
        reasons.append("possible out-of-distribution language/format")
    for s in fi.failed_stages:
        reasons.append(f"stage failed: {s}")
    level = "high" if len(reasons) >= 3 or not fi.language_supported or fi.model_status != "loaded" else \
        "medium" if reasons else "low"
    return {"level": level, "reasons": reasons}


def impact_and_priority(decision: dict, actions: list[str], unc_level: str) -> dict:
    high = sorted(set(actions) & HIGH_IMPACT_ACTIONS)
    medium = sorted(set(actions) & {"click_link", "open_attachment", "call_number", "payment_request", "reply_new_recipient"})
    impact = "high" if high else "medium" if medium else "low"
    v = decision["verdict"]
    if v in ("LIKELY_PHISHING", "AI_INJECTION_SUSPECTED"):
        pr = "P1" if impact == "high" else "P2"
    elif v == "SUSPICIOUS_REVIEW":
        pr = "P2" if impact == "high" else "P3"
    elif v == "INSUFFICIENT_EVIDENCE":
        pr = "P3"
    else:
        pr = "P4"
    score = decision["risk_score"] * (1.3 if impact == "high" else 1.1 if impact == "medium" else 1.0)
    score += {"high": 8, "medium": 4, "low": 0}[unc_level] if v != "NO_STRONG_INDICATORS" else 0
    return {"potential_impact": impact, "impact_actions": high or medium, "priority": pr,
            "priority_score": round(min(score, 150.0), 1),
            "rationale": f"{decision['verdict_label']} · potential impact {impact}" +
                         (f" ({', '.join(high or medium)})" if (high or medium) else "")}
