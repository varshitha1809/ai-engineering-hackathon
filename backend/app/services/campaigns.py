"""Signature 3 — Campaign DNA: explainable relationships between retained messages.

Edges are created ONLY from concrete shared evidence:
  exact   — same normalised URL, attachment SHA-256, Reply-To address, bank-account reference, phone number
  infra   — same non-common link/sender/reply-to domain
  content — near-duplicate body (Jaccard of word 5-shingles after dropping boilerplate shingles)
  context — same configured VIP/vendor identity impersonated from different addresses
Tactic overlap or generic words ("urgent", "verify") never create an edge.
Campaigns are connected components over edges with strength >= 0.5; weaker edges are shown but do not
merge clusters. No attacker attribution is made.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from datetime import datetime, timezone

from ..db import Database, dumps

EDGE_RULES = {
    "url": ("shared_url", 0.95, "Both messages link to the same normalised URL"),
    "sha256": ("shared_attachment_hash", 0.95, "Both messages carry an attachment with the same SHA-256"),
    "reply_to_address": ("shared_reply_to", 0.85, "Replies from both messages go to the same address"),
    "bank_account": ("shared_bank_account", 0.9, "Both messages reference the same bank account (hashed)"),
    "phone": ("shared_phone", 0.7, "Both messages give the same phone number (hashed)"),
    "domain": ("shared_link_domain", 0.75, "Both messages link to the same non-common registrable domain"),
    "reply_to_domain": ("shared_reply_to_domain", 0.6, "Replies go to the same non-common domain"),
    "sender_domain": ("shared_sender_domain", 0.45, "Same sender domain (weak: organisations send many messages)"),
    "sender_address": ("same_sender_address", 0.4, "Same sender address (weak on its own)"),
}
CAMPAIGN_MIN_STRENGTH = 0.5
NEAR_DUP_THRESHOLD = 0.55
SIMILAR_THRESHOLD = 0.3
_TOK = re.compile(r"[a-z0-9]+")


def strength_label(s: float) -> str:
    return "strong" if s >= 0.8 else "moderate" if s >= 0.5 else "weak"


def shingles(text: str, k: int = 5) -> set[str]:
    toks = _TOK.findall((text or "").lower())
    if len(toks) < k:
        return {" ".join(toks)} if toks else set()
    return {" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1)}


def fingerprint(text: str) -> str:
    """64-bit SimHash of word tokens, displayed as a short content fingerprint."""
    v = [0] * 64
    for tok, w in Counter(_TOK.findall((text or "").lower())).items():
        h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=8).digest(), "big")
        for i in range(64):
            v[i] += w if (h >> i) & 1 else -w
    return f"{sum(1 << i for i in range(64) if v[i] > 0):016x}"


class CampaignService:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ candidate edges for one message
    def candidate_edges(self, analysis_id: str, indicators: list[dict], body_text: str, profile_tags: list[str],
                        limit: int = 3000) -> list[dict]:
        edges: dict[tuple[str, str], dict] = {}
        for ind in indicators:
            if not ind.get("correlate", True) or ind["type"] not in EDGE_RULES:
                continue
            etype, strength, why = EDGE_RULES[ind["type"]]
            rows = self.db.all(
                "SELECT DISTINCT ai.analysis_id AS aid FROM analysis_indicators ai JOIN indicators i ON i.id = ai.indicator_id "
                "WHERE i.type=? AND i.value=? AND ai.analysis_id != ? LIMIT 500", (ind["type"], ind["value"], analysis_id))
            for r in rows:
                key = (r["aid"], etype)
                e = edges.setdefault(key, {"other": r["aid"], "edge_type": etype, "strength": strength, "explanation": why,
                                           "evidence": []})
                e["evidence"].append({"indicator_type": ind["type"], "value": ind["display_value"]})
        # near-duplicate / similar content
        mine = shingles(body_text)
        if len(mine) >= 5:
            others = self.db.all("SELECT id, body_text FROM analyses WHERE id != ? AND body_text IS NOT NULL "
                                 "ORDER BY created_at DESC LIMIT ?", (analysis_id, limit))
            sets = {o["id"]: shingles(o["body_text"]) for o in others}
            df = Counter()
            for s in sets.values():
                df.update(s)
            n_docs = len(sets) + 1
            # boilerplate: shingles present in >30% of retained messages (only meaningful with >=10 messages)
            boiler = {s for s, c in df.items() if n_docs >= 10 and c / n_docs > 0.3}
            a = mine - boiler
            for oid, s in sets.items():
                b = s - boiler
                if len(b) < 5 or not a:
                    continue
                inter = len(a & b)
                if not inter:
                    continue
                j = inter / len(a | b)
                if j >= NEAR_DUP_THRESHOLD:
                    edges[(oid, "near_duplicate_content")] = {
                        "other": oid, "edge_type": "near_duplicate_content", "strength": round(min(0.95, 0.5 + j / 2), 3),
                        "explanation": f"Message bodies are near-duplicates (Jaccard {j:.2f} on word 5-shingles, boilerplate removed)",
                        "evidence": [{"indicator_type": "content_similarity", "value": f"jaccard={j:.3f}, shared shingles={inter}"}]}
                elif j >= SIMILAR_THRESHOLD:
                    edges[(oid, "similar_content")] = {
                        "other": oid, "edge_type": "similar_content", "strength": round(0.25 + j / 2, 3),
                        "explanation": f"Partially similar wording (Jaccard {j:.2f}); weak evidence on its own",
                        "evidence": [{"indicator_type": "content_similarity", "value": f"jaccard={j:.3f}, shared shingles={inter}"}]}
        # same impersonated identity (configured profile) from different addresses
        for tag in profile_tags:
            rows = self.db.all("SELECT DISTINCT analysis_id FROM findings WHERE tags_json LIKE ? AND analysis_id != ? "
                               "AND category LIKE 'identity.%impersonation'", (f'%"{tag}"%', analysis_id))
            for r in rows:
                edges[(r["analysis_id"], "same_impersonated_identity")] = {
                    "other": r["analysis_id"], "edge_type": "same_impersonated_identity", "strength": 0.6,
                    "explanation": "Both messages impersonate the same configured VIP/vendor profile from addresses not on record",
                    "evidence": [{"indicator_type": "profile", "value": tag}]}
        for e in edges.values():
            e["strength_label"] = strength_label(e["strength"])
        return sorted(edges.values(), key=lambda e: -e["strength"])

    # ------------------------------------------------------------------ persist edges + rebuild clusters
    def persist_edges(self, analysis_id: str, edges: list[dict]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.db.transaction() as c:
            for e in edges:
                a, b = sorted([analysis_id, e["other"]])
                exists = c.execute("SELECT id FROM campaign_edges WHERE src=? AND dst=? AND edge_type=?", (a, b, e["edge_type"])).fetchone()
                if exists:
                    continue
                c.execute("INSERT INTO campaign_edges (campaign_id, src, dst, edge_type, strength, strength_label, evidence_json, "
                          "explanation, created_at) VALUES (NULL,?,?,?,?,?,?,?,?)",
                          (a, b, e["edge_type"], e["strength"], e["strength_label"], dumps(e["evidence"]), e["explanation"], now))
        self.rebuild()

    def rebuild(self) -> None:
        edges = self.db.all("SELECT id, src, dst, strength, edge_type FROM campaign_edges")
        parent: dict[str, str] = {}

        def find(x):
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for e in edges:
            if e["strength"] >= CAMPAIGN_MIN_STRENGTH:
                ra, rb = find(e["src"]), find(e["dst"])
                if ra != rb:
                    parent[max(ra, rb)] = min(ra, rb)
        comps: dict[str, list[str]] = {}
        for x in list(parent):
            comps.setdefault(find(x), []).append(x)
        comps = {k: sorted(v) for k, v in comps.items() if len(v) >= 2}
        now = datetime.now(timezone.utc).isoformat()
        old = {r["id"]: r for r in self.db.all("SELECT id, created_at, label FROM campaigns")}
        with self.db.transaction() as c:
            c.execute("DELETE FROM campaign_members")
            c.execute("DELETE FROM campaigns")
            c.execute("UPDATE campaign_edges SET campaign_id=NULL")
            for root, members in comps.items():
                cid = "CMP-" + hashlib.sha1(members[0].encode()).hexdigest()[:8].upper()
                q = ",".join("?" * len(members))
                rows = [dict(r) for r in c.execute(
                    f"SELECT id, risk_score, verdict, created_at, email_date, actions_json, tactics_json, subject FROM analyses WHERE id IN ({q})",
                    members).fetchall()]
                medges = [dict(r) for r in c.execute(
                    f"SELECT edge_type, strength, evidence_json FROM campaign_edges WHERE src IN ({q}) AND dst IN ({q})",
                    members + members).fetchall()]
                c.execute(f"UPDATE campaign_edges SET campaign_id=? WHERE src IN ({q}) AND dst IN ({q})", [cid, *members, *members])
                summary, sev_score, low_slow, first, last = self._summarise(rows, medges)
                sev = "critical" if sev_score >= 80 else "high" if sev_score >= 60 else "medium" if sev_score >= 40 else "low"
                label = summary["label"]
                c.execute("INSERT INTO campaigns (id, created_at, updated_at, label, severity, severity_score, member_count, "
                          "first_seen, last_seen, low_and_slow, summary_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                          (cid, old.get(cid, {}).get("created_at") or now, now, label, sev, sev_score, len(members),
                           first, last, int(low_slow), dumps(summary)))
                for m in members:
                    c.execute("INSERT INTO campaign_members (campaign_id, analysis_id) VALUES (?,?)", (cid, m))

    @staticmethod
    def _summarise(rows: list[dict], medges: list[dict]):
        import json
        risks = [r["risk_score"] or 0 for r in rows]
        times = sorted((r["email_date"] or r["created_at"]) for r in rows)
        etypes = Counter(e["edge_type"] for e in medges)
        shared = Counter()
        for e in medges:
            for ev in json.loads(e["evidence_json"] or "[]"):
                shared[f"{ev['indicator_type']}: {ev['value']}"] += 1
        actions, tactics = set(), set()
        for r in rows:
            actions |= set(json.loads(r["actions_json"] or "{}"))
            tactics |= set(json.loads(r["tactics_json"] or "{}"))
        high_impact = bool(actions & {"provide_credentials", "provide_mfa_code", "change_bank_details", "payroll_change",
                                      "buy_gift_cards", "disclose_sensitive_data"})
        max_strength = max((e["strength"] for e in medges), default=0)
        n = len(rows)
        # severity: evidence strength, worst member, size (log) and impact - not a sum of member scores
        sev = 0.45 * max(risks) + 25 * max_strength + min(8 * math.log2(n), 16) + (12 if high_impact else 0)
        sev = round(min(sev, 100.0), 1)
        try:
            span_days = (datetime.fromisoformat(times[-1]) - datetime.fromisoformat(times[0])).total_seconds() / 86400
        except Exception:
            span_days = 0.0
        # low-and-slow: >=3 related messages, most of which individually stayed below the likely-phishing threshold,
        # spread over at least a day (local observation/Date header times only)
        low_slow = n >= 3 and sum(1 for r in risks if r < 65) >= max(2, n // 2 + 1) and span_days >= 1
        top_type = etypes.most_common(1)[0][0] if etypes else "related"
        label = f"{top_type.replace('_', ' ')} cluster ({n} messages)"
        summary = {"label": label, "edge_types": dict(etypes), "shared_evidence": shared.most_common(12),
                   "requested_actions": sorted(actions), "tactics": sorted(tactics), "max_member_risk": max(risks),
                   "mean_member_risk": round(sum(risks) / n, 1), "max_edge_strength": max_strength,
                   "verdicts": dict(Counter(r["verdict"] for r in rows)), "span_days": round(span_days, 2),
                   "high_impact": high_impact,
                   "low_and_slow_reason": ("≥3 related messages, most individually below the likely-phishing threshold"
                                           + (f", spread over {span_days:.1f} days" if span_days >= 1 else "")) if low_slow else "",
                   "attribution_note": "Shared evidence shows these messages are related; it does not identify a common attacker."}
        return summary, sev, low_slow, times[0], times[-1]
