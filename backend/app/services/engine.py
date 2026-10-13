"""Analysis engine — the end-to-end flow from the architecture diagram:

parse/validate → detectors (social engineering, identity, URL, attachment, AI-injection) → trained text model
→ threat-intel lookup → related-message correlation → risk fusion → reconstruction/explanations → persistence
(analysis, findings, indicators, case, audit, campaign edges).

Each stage records ok/failed/unavailable in `stage_status`; a failed stage can never turn into a "safe" verdict.
"""
from __future__ import annotations

import hashlib
import re
import time
import uuid
import zlib
from datetime import datetime, timezone

from ..analysis import fusion
from ..analysis.context import AnalysisContext, Profile
from ..analysis.detectors import ai_injection, identity, links_attachments, social_engineering
from ..analysis.detectors.social_engineering import HIGH_IMPACT_ACTIONS
from ..analysis.evidence import Finding
from ..analysis.model import TextModel
from ..config import FUSION_VERSION, RULES_VERSION, Settings
from ..db import Database
from ..email_processing.parser import EmailParseError, ParsedEmail, parse_input
from ..investigation import reconstruction
from ..threat_intel.providers import LocalIndicatorProvider, VirusTotalProvider
from . import indicators as ind_mod
from .audit import audit
from .campaigns import CampaignService

_STOP = set("the a an and or to of in for on is are be with this that you your we our it as at by from have has will "
            "please not can if was were i me my us they them their there here all any about would could should".split())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str = "A") -> str:
    return f"{prefix}-{datetime.now(timezone.utc).strftime('%y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


def redact_preview(text: str, n: int = 280) -> str:
    t = re.sub(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", "[email]", text or "")
    t = re.sub(r"\b\d[\d\s-]{7,}\d\b", "[number]", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:n] + ("…" if len(t) > n else "")


def language_supported(text: str) -> bool:
    toks = re.findall(r"[a-zA-ZÀ-￿']+", text.lower())
    if len(toks) < 15:
        return True  # too short to judge; short-content uncertainty is reported separately
    latin = sum(1 for t in toks if re.fullmatch(r"[a-z']+", t))
    stop = sum(1 for t in toks if t in _STOP)
    return latin / len(toks) >= 0.7 and stop / len(toks) >= 0.04


class Engine:
    def __init__(self, db: Database, model: TextModel, settings: Settings):
        self.db = db
        self.model = model
        self.settings = settings
        self.local_ti = LocalIndicatorProvider(db)
        self.vt = VirusTotalProvider(settings.virustotal_api_key, settings.enable_external_lookups)
        self.campaigns = CampaignService(db)
        self.latencies: list[float] = []

    # ---------------------------------------------------------------- helpers
    def profiles(self) -> list[Profile]:
        return [Profile(r["id"], r["kind"], r["name"], [e.lower() for e in r["emails_json"] or []],
                        [d.lower() for d in r["domains_json"] or []]) for r in self.db.all("SELECT * FROM profiles")]

    def providers_status(self) -> list[dict]:
        out = []
        for p in (self.local_ti, self.vt):
            ok, why = p.available()
            out.append({"provider": p.name, "available": ok, "detail": why})
        return out

    # ---------------------------------------------------------------- main entry
    def analyze(self, raw: bytes, input_source: str, subject: str | None = None, sender: str | None = None,
                data_label: str = "user", batch_id: str | None = None, persist: bool = True,
                correlate: bool = True, analysis_id: str | None = None, reason: str = "submitted",
                profiles_override: list[Profile] | None = None, org_domains_override: list[str] | None = None) -> dict:
        t0 = time.perf_counter()
        aid = analysis_id or new_id()
        stage: dict[str, dict] = {}
        try:
            pe = parse_input(raw, input_source, self.settings.max_email_bytes, subject, sender)
            parse_ok = True
            stage.update(pe.stage_status)
        except EmailParseError:
            raise
        except Exception as exc:  # malformed beyond the lenient parser: explicit failure, not a safe verdict
            pe = ParsedEmail(input_source=input_source, raw_sha256=hashlib.sha256(raw).hexdigest(), raw_size=len(raw),
                             headers_present=False)
            parse_ok = False
            stage["parse"] = {"status": "failed", "detail": f"{type(exc).__name__}"}

        ctx = AnalysisContext(parsed=pe, org_domains=org_domains_override or self.settings.org_domains,
                              trusted_authserv_ids=self.settings.trusted_authserv_ids,
                              profiles=profiles_override if profiles_override is not None else self.profiles(),
                              sender_history_count=(self.db.scalar("SELECT COUNT(*) FROM analyses WHERE from_addr=?",
                                                                   (pe.from_addr,)) or 0) if (persist and pe.from_addr) else 0)
        for name, fn in (("social_engineering", social_engineering.run), ("identity", identity.run),
                         ("urls", links_attachments.run_urls), ("attachments", links_attachments.run_attachments),
                         ("ai_injection", ai_injection.run)):
            ts = time.perf_counter()
            try:
                fn(ctx)
                stage[name] = {"status": "ok", "ms": round((time.perf_counter() - ts) * 1000, 2)}
            except Exception as exc:
                stage[name] = {"status": "failed", "detail": type(exc).__name__}
                ctx.collector.add(category=f"stage.{name}_failed", component="coverage", severity="medium",
                                  title=f"Detector '{name}' failed", observed_value=type(exc).__name__, source_location="pipeline",
                                  method="rule", version=RULES_VERSION, confidence=0.0, status="unavailable",
                                  explanation="This layer did not contribute; the verdict accounts for the missing layer.")

        # ---- trained text model
        model_out = None
        body = pe.visible_text or ""
        if self.model.status == "loaded" and (body.strip() or pe.subject):
            try:
                model_out = self.model.predict(pe.subject, body)
                stage["text_model"] = {"status": "ok", "ms": model_out["latency_ms"], "version": self.model.version}
                pos = [c["feature"].strip() for c in model_out["top_contributions"] if c["contribution"] > 0][:5]
                ctx.collector.add(category="model.text_score", component="text_model",
                                  severity="high" if model_out["score"] >= 0.85 else "medium" if model_out["predicted_label"] else "info",
                                  title=f"Trained text classifier score {model_out['score']:.2f}",
                                  observed_value=f"score={model_out['score']:.3f}, threshold={model_out['threshold']:.3f}; "
                                                 f"top features: {', '.join(pos) or 'none'}",
                                  source_location="subject+body", method="model", version=self.model.version,
                                  confidence=model_out["score"], status="observed",
                                  explanation="TF-IDF + linear SVM trained on MeAJOR + Nazario_5 (body text only). It has not "
                                              "seen headers, attachments or hidden HTML; those are covered by rule layers.")
            except Exception as exc:
                stage["text_model"] = {"status": "failed", "detail": f"{type(exc).__name__}"}
        else:
            stage["text_model"] = {"status": "failed" if self.model.status != "loaded" else "skipped",
                                   "detail": self.model.error or ("no text content" if self.model.status == "loaded" else "")}
        if stage["text_model"]["status"] != "ok":
            ctx.collector.add(category="model.unavailable", component="coverage", severity="medium",
                              title="Trained text model did not run", observed_value=stage["text_model"].get("detail", ""),
                              source_location="pipeline", method="model", version=self.model.version, confidence=0.0,
                              status="unavailable", explanation="Without the model, a benign verdict cannot be supported "
                                                                "by content analysis; see verdict policy.")

        # ---- indicators + threat intelligence
        inds = ind_mod.extract(ctx)
        ti_stats = {"looked_up": 0, "malicious": 0, "suspicious": 0, "unknown": 0, "providers": []}
        rep_malicious = False
        try:
            providers = [self.local_ti] + ([self.vt] if self.vt.available()[0] else [])
            ti_stats["providers"] = [p.name for p in providers]
            for ind in inds:
                if ind["type"] not in ("url", "domain", "sha256", "sender_domain", "reply_to_domain", "sender_address",
                                       "reply_to_address"):
                    continue
                for p in providers:
                    if p is self.vt and ind["type"] not in ("url", "domain", "sha256"):
                        continue
                    # a malicious domain IOC also applies when that domain is the sender / reply-to domain
                    lookup_type = "domain" if ind["type"] in ("sender_domain", "reply_to_domain") else ind["type"]
                    res = p.lookup(lookup_type, ind["value"])
                    ti_stats["looked_up"] += 1
                    ctx.reputation.append(res.to_dict() | {"location": ind["location"]})
                    if res.verdict in ("malicious", "suspicious"):
                        ti_stats[res.verdict] += 1
                        strong = res.verdict == "malicious"
                        rep_malicious |= strong
                        ctx.collector.add(category=f"reputation.{res.verdict}", component="reputation",
                                          severity="critical" if strong else "medium",
                                          title=f"{ind['type'].replace('_', ' ').title()} listed as {res.verdict} ({res.source})",
                                          observed_value=ind["display_value"], source_location=ind["location"], method="provider",
                                          version=f"{p.name}", confidence=0.95 if strong else 0.6, status="observed",
                                          explanation=f"Provider '{p.name}', source '{res.source}', checked {res.checked_at}. "
                                                      f"{res.detail}".strip())
                    else:
                        ti_stats["unknown"] += 1
            stage["threat_intel"] = {"status": "ok", "detail": f"{ti_stats['looked_up']} lookup(s); unknown means unknown"}
        except Exception as exc:
            stage["threat_intel"] = {"status": "failed", "detail": type(exc).__name__}

        # ---- related-message correlation (earlier identification of related messages)
        cand_edges: list[dict] = []
        if persist and correlate:
            try:
                profile_tags = sorted({t for f in ctx.collector.findings for t in f.tags if t.startswith("profile:")
                                       and f.category.endswith("impersonation")})
                # indicators of this message are not yet stored; compare by value
                cand_edges = self.campaigns.candidate_edges(aid, inds, body, profile_tags)
                strong_rel = [e for e in cand_edges if e["strength"] >= 0.5]
                if strong_rel:
                    others = {e["other"] for e in strong_rel}
                    q = ",".join("?" * len(others))
                    rows = {r["id"]: r for r in self.db.all(f"SELECT id, verdict, risk_score FROM analyses WHERE id IN ({q})", list(others))}
                    flagged = [e for e in strong_rel if rows.get(e["other"], {}).get("verdict") in ("LIKELY_PHISHING", "AI_INJECTION_SUSPECTED")]
                    best = (flagged or strong_rel)[0]
                    conf = 0.6 if flagged and best["strength"] >= 0.8 else 0.4 if flagged else 0.15
                    ctx.collector.add(category="campaign.related_messages", component="context",
                                      severity="high" if conf >= 0.6 else "low",
                                      title=f"Related to {len(others)} retained message(s)"
                                            + (f", {len({e['other'] for e in flagged})} previously assessed as malicious" if flagged else ""),
                                      observed_value=f"{best['edge_type']} with {best['other']}: {best['evidence'][0]['value']}",
                                      source_location="campaign graph", method="rule", version=RULES_VERSION, confidence=conf,
                                      status="observed", explanation=best["explanation"] + ". Relationship evidence, not attribution.",
                                      tags=[f"related:{e['other']}" for e in strong_rel[:10]])
                stage["correlation"] = {"status": "ok", "detail": f"{len(cand_edges)} candidate relationship(s)"}
            except Exception as exc:
                stage["correlation"] = {"status": "failed", "detail": type(exc).__name__}
        else:
            stage["correlation"] = {"status": "skipped", "detail": "not persisted (benchmark/replay)"}

        # ---- fusion
        findings = ctx.collector.findings
        strengths = fusion.group_strengths(findings, model_out["score"] if model_out else None)
        high_actions = sorted(set(ctx.actions) & (HIGH_IMPACT_ACTIONS - {"manipulate_ai_assistant"}))
        identity_verified = any(
            (pe.from_addr in p.emails or (pe.from_domain and pe.from_domain in p.domains)) for p in ctx.profiles
        ) and strengths.get("identity", 0) < 0.3
        failed = [k for k, v in stage.items() if v.get("status") == "failed"]
        fi = fusion.FusionInput(strengths=strengths, model_status="loaded" if model_out else self.model.status if self.model.status != "loaded" else "skipped",
                                model_score=model_out["score"] if model_out else None, model_threshold=self.model.threshold,
                                high_impact_actions=high_actions, identity_verified=identity_verified,
                                word_count=len(re.findall(r"\w+", f"{pe.subject} {body}")), headers_present=pe.headers_present,
                                parse_ok=parse_ok, language_supported=language_supported(body),
                                reputation_malicious=rep_malicious, failed_stages=failed)
        decision = fusion.decide(fi)
        unc = fusion.uncertainty(fi, decision)
        impact = fusion.impact_and_priority(decision, list(ctx.actions), unc["level"])
        summary = pe.summary()
        recon = reconstruction.build(findings, summary, decision, model_out, ctx.actions, ctx.tactics, impact)
        expl = reconstruction.explanations(decision, findings, strengths, model_out, unc)
        recs = self._recommendations(decision, recon, impact)
        latency = round((time.perf_counter() - t0) * 1000, 1)
        self.latencies = (self.latencies + [latency])[-500:]

        result = {
            "id": aid, "created_at": now_iso(), "input_source": input_source, "data_label": data_label, "batch_id": batch_id,
            "parsed": summary, "verdict": decision["verdict"], "verdict_label": decision["verdict_label"],
            "risk_score": decision["risk_score"], "score_semantics": "0-100 policy risk score (not a probability)",
            "decision": decision, "uncertainty": unc, "impact": impact, "strengths": strengths,
            "fusion_input": fi.__dict__, "model": model_out, "tactics": ctx.tactics, "actions": ctx.actions,
            "findings": [f.to_dict() for f in findings], "reconstruction": recon, "explanation": expl,
            "recommendations": recs, "stage_status": stage, "threat_intel": {"stats": ti_stats, "results": ctx.reputation[:50]},
            "indicators": inds, "related": [{k: e[k] for k in ("other", "edge_type", "strength", "strength_label", "explanation", "evidence")}
                                            for e in cand_edges[:25]],
            "versions": {"model": self.model.version, "rules": RULES_VERSION, "fusion": FUSION_VERSION},
            "latency_ms": latency, "body_text": body,
        }
        if persist:
            self._persist(result, raw, pe, findings, inds, cand_edges, reason)
        return result

    def _recommendations(self, decision: dict, recon: dict, impact: dict) -> list[dict]:
        v = decision["verdict"]
        recs = []
        if v == "LIKELY_PHISHING":
            recs.append({"action": "quarantine_local", "text": "Quarantine this message in the local case store and block its indicators locally."})
        if v == "AI_INJECTION_SUSPECTED":
            recs.append({"action": "ai_exclusion", "text": "Exclude this message from AI-assistant processing; treat embedded instructions as untrusted."})
        if v in ("LIKELY_PHISHING", "SUSPICIOUS_REVIEW", "AI_INJECTION_SUSPECTED"):
            recs.append({"action": "banner", "text": "Show the recipient a warning banner (local recommendation)."})
        if impact["potential_impact"] == "high" and v != "NO_STRONG_INDICATORS":
            recs.append({"action": "escalate", "text": "High potential impact: escalate to an analyst before anyone acts on the request."})
        for s in recon["verification_steps"]:
            recs.append({"action": "verify", "text": s["step"], "evidence": s["resolves_uncertainty_in"]})
        if v == "NO_STRONG_INDICATORS":
            recs.append({"action": "none", "text": "No action required by policy; unavailable checks are listed under stage status."})
        if v == "INSUFFICIENT_EVIDENCE":
            recs.append({"action": "provide_more", "text": "Upload the original .eml (with headers) or route to an analyst."})
        return recs

    # ---------------------------------------------------------------- persistence
    def _persist(self, r: dict, raw: bytes, pe: ParsedEmail, findings: list[Finding], inds: list[dict],
                 edges: list[dict], reason: str) -> None:
        aid = r["id"]
        now = r["created_at"]
        existing = self.db.one("SELECT id, original_verdict, original_risk_score, local_state, created_at FROM analyses WHERE id=?", (aid,))
        with self.db.transaction() as c:
            row = {
                "id": aid, "created_at": existing["created_at"] if existing else now, "input_source": r["input_source"],
                "data_label": r["data_label"], "batch_id": r["batch_id"], "subject": pe.subject[:300],
                "from_addr": pe.from_addr, "from_display": pe.from_display[:200], "from_domain": pe.from_domain,
                "reply_to_addr": pe.reply_to_addr, "email_date": pe.date_iso, "raw_sha256": pe.raw_sha256,
                "preview": redact_preview(r["body_text"]), "body_text": r["body_text"][:50_000],
                "parsed_json": r["parsed"], "verdict": r["verdict"], "verdict_label": r["verdict_label"],
                "risk_score": r["risk_score"], "strengths_json": r["strengths"], "fusion_input_json": r["fusion_input"],
                "decision_json": r["decision"], "uncertainty_json": r["uncertainty"], "model_json": r["model"],
                "tactics_json": r["tactics"], "actions_json": r["actions"], "impact_json": r["impact"],
                "priority": r["impact"]["priority"], "priority_score": r["impact"]["priority_score"],
                "reconstruction_json": r["reconstruction"], "explanation_json": {"explanation": r["explanation"],
                                                                                  "recommendations": r["recommendations"],
                                                                                  "threat_intel": r["threat_intel"]},
                "stage_status_json": r["stage_status"], "model_version": r["versions"]["model"],
                "rules_version": r["versions"]["rules"], "fusion_version": r["versions"]["fusion"],
                "latency_ms": r["latency_ms"],
                "original_verdict": existing["original_verdict"] if existing else r["verdict"],
                "original_risk_score": existing["original_risk_score"] if existing else r["risk_score"],
                "local_state": existing["local_state"] if existing else "delivered",
            }
            self.db.insert("analyses", row, c, replace=True)
            c.execute("DELETE FROM findings WHERE analysis_id=?", (aid,))
            c.execute("DELETE FROM analysis_indicators WHERE analysis_id=?", (aid,))
            if self.settings.retain_raw and not existing:
                c.execute("INSERT OR REPLACE INTO raw_inputs (analysis_id, created_at, raw) VALUES (?,?,?)",
                          (aid, now, zlib.compress(raw)))
            loc_to_ind: dict[str, list[int]] = {}
            for ind in inds:
                c.execute("INSERT INTO indicators (type, value, display_value, first_seen_local, last_seen_local, sightings) "
                          "VALUES (?,?,?,?,?,1) ON CONFLICT(type, value) DO UPDATE SET last_seen_local=excluded.last_seen_local, "
                          "sightings=sightings+1", (ind["type"], ind["value"], ind["display_value"], now, now))
                iid = c.execute("SELECT id FROM indicators WHERE type=? AND value=?", (ind["type"], ind["value"])).fetchone()[0]
                c.execute("INSERT OR IGNORE INTO analysis_indicators (analysis_id, indicator_id, location) VALUES (?,?,?)",
                          (aid, iid, ind["location"]))
                ind["id"] = iid
                loc_to_ind.setdefault(ind["location"].split(" ")[0], []).append(iid)
            for f in findings:
                key = f.source_location.split(" ")[0]
                f.related_indicator_ids = loc_to_ind.get(key, [])
                f.analysis_id = aid
                d = f.to_dict()
                self.db.insert("findings", {
                    "analysis_id": aid, "finding_id": d["finding_id"], "category": d["category"], "component": d["component"],
                    "severity": d["severity"], "title": d["title"], "observed_value": d["observed_value"],
                    "source_location": d["source_location"], "method": d["method"], "version": d["version"],
                    "confidence": d["confidence"], "status": d["status"], "explanation": d["explanation"],
                    "timestamp": d["timestamp"], "related_indicator_ids": d["related_indicator_ids"],
                    "related_finding_ids": d["related_finding_ids"], "span_json": d["span"], "tags_json": d["tags"]}, c)
            c.execute("INSERT INTO analysis_versions (analysis_id, created_at, reason, verdict, risk_score, model_version, "
                      "rules_version, detail_json) VALUES (?,?,?,?,?,?,?,?)",
                      (aid, now, reason, r["verdict"], r["risk_score"], r["versions"]["model"], r["versions"]["rules"],
                       '{"strong_groups": %d}' % len(r["decision"]["strong_groups"])))
            # case management: everything except "no strong indicators" enters the analyst queue
            case = c.execute("SELECT id, status FROM cases WHERE analysis_id=?", (aid,)).fetchone()
            if r["verdict"] != "NO_STRONG_INDICATORS" and not case:
                cid = "C-" + aid.split("-", 1)[1]
                c.execute("INSERT INTO cases (id, analysis_id, status, priority, priority_score, assignee, created_at, updated_at, "
                          "notes_json, resolution) VALUES (?,?,?,?,?,?,?,?,?,?)",
                          (cid, aid, "open", r["impact"]["priority"], r["impact"]["priority_score"], None, now, now, "[]", None))
            elif case:
                c.execute("UPDATE cases SET priority=?, priority_score=?, updated_at=? WHERE id=?",
                          (r["impact"]["priority"], r["impact"]["priority_score"], now, case["id"]))
        audit(self.db, "analysis." + ("rescored" if existing else "created"), "system", "analysis", aid, "ok",
              f"verdict={r['verdict']} risk={r['risk_score']} source={r['input_source']} reason={reason}")
        if edges:
            self.campaigns.persist_edges(aid, edges)

    # ---------------------------------------------------------------- re-score retained analyses
    def rescore(self, analysis_id: str, reason: str) -> dict | None:
        row = self.db.one("SELECT a.input_source, a.data_label, a.batch_id, a.verdict, a.risk_score, r.raw FROM analyses a "
                          "LEFT JOIN raw_inputs r ON r.analysis_id = a.id WHERE a.id=?", (analysis_id,))
        if not row:
            return None
        if row["raw"] is None:
            return {"id": analysis_id, "status": "unavailable", "detail": "raw content not retained; cannot re-analyse"}
        before = {"verdict": row["verdict"], "risk_score": row["risk_score"]}
        res = self.analyze(zlib.decompress(row["raw"]), row["input_source"], data_label=row["data_label"],
                           batch_id=row["batch_id"], persist=True, analysis_id=analysis_id, reason=reason)
        return {"id": analysis_id, "status": "rescored", "before": before,
                "after": {"verdict": res["verdict"], "risk_score": res["risk_score"]},
                "changed": before["verdict"] != res["verdict"]}
