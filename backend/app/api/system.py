"""Health, system status, dashboard aggregates, model/dataset workspace and settings (no secrets)."""
from __future__ import annotations

import json
from collections import Counter

import numpy as np
from fastapi import APIRouter

from ..config import FUSION_VERSION, REPO_ROOT, RULES_VERSION, settings
from ..analysis.fusion import DEFAULT_POLICY, WEIGHTS
from ..services.indicators import COMMON_DOMAINS
from ..state import state

router = APIRouter(prefix="/api/v1", tags=["system"])


def _read_json(p):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


@router.get("/health")
def health():
    try:
        state.db.scalar("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False
    m = state.model
    return {"api": "ok", "database": "ok" if db_ok else "error",
            "model": {"status": m.status, "version": m.version, "error": m.error, "threshold": m.threshold if m.status == "loaded" else None},
            "providers": state.engine.providers_status(), "rules_version": RULES_VERSION, "fusion_version": FUSION_VERSION,
            "started_at": state.started_at}


@router.get("/system/status")
def system_status():
    lat = state.engine.latencies
    fails = Counter()
    for r in state.db.all("SELECT stage_status_json FROM analyses ORDER BY created_at DESC LIMIT 500"):
        for k, v in (r["stage_status_json"] or {}).items():
            if isinstance(v, dict) and v.get("status") == "failed":
                fails[k] += 1
    last_eval = state.db.one("SELECT id, suite, status, progress, total, started_at, finished_at FROM evaluation_runs "
                             "ORDER BY started_at DESC LIMIT 1")
    timeouts = state.db.scalar("SELECT COUNT(*) FROM audit_events WHERE action='analysis.timeout'")
    return {**health(), "latency_ms": {"n": len(lat), "p50": round(float(np.percentile(lat, 50)), 1) if lat else None,
                                       "p95": round(float(np.percentile(lat, 95)), 1) if lat else None,
                                       "scope": "analyses since server start"},
            "stage_failures_last_500": dict(fails), "timeouts": timeouts, "last_benchmark": last_eval,
            "integrations": [
                {"name": "Local IOC store", "status": "connected", "detail": "built-in"},
                {"name": "VirusTotal", "status": "connected" if state.engine.vt.available()[0] else "not configured",
                 "detail": state.engine.vt.available()[1]},
                {"name": "Gmail / Microsoft Graph / IMAP", "status": "not connected", "detail": "no OAuth configuration; "
                 "mailbox actions are local sandbox records only"},
                {"name": "SIEM / SOAR / TAXII", "status": "not connected", "detail": "local JSON/CSV/STIX file export available"},
                {"name": "LLM explanation", "status": "not configured", "detail": "deterministic evidence-templated explanations are used"},
                {"name": "OCR / QR extraction", "status": "not enabled", "detail": "image/PDF text is not extracted; disclosed per analysis"},
                {"name": "Isolated page renderer", "status": "not configured", "detail": "URLs are analysed statically; no URL is fetched"},
            ]}


@router.get("/settings")
def get_settings():
    return {"org_domains": settings.org_domains, "trusted_authserv_ids": settings.trusted_authserv_ids,
            "retain_raw": settings.retain_raw, "max_email_bytes": settings.max_email_bytes,
            "max_batch_items": settings.max_batch_items, "rate_limit_per_min": settings.rate_limit_per_min,
            "api_key_required": bool(settings.api_key), "external_lookups_enabled": settings.enable_external_lookups,
            "virustotal_key_present": bool(settings.virustotal_api_key), "fusion_weights": WEIGHTS,
            "verdict_policy": DEFAULT_POLICY, "env_help": "Copy .env.example to .env and set values; secrets are never returned by the API."}


@router.get("/model")
def model_workspace():
    reports = REPO_ROOT / "data" / "reports"
    profile = _read_json(reports / "dataset_profile.json") or {}
    meta = state.model.meta or _read_json(settings.model_dir / "model_metadata.json") or {}
    runs = []
    p = reports / "training_runs.jsonl"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            try:
                runs.append(json.loads(line))
            except ValueError:
                pass
    slim_profile = {k: profile.get(k) for k in ("prep_version", "seed", "generated_at", "deduplication", "splits",
                                                "cross_dataset_overlap", "external_test", "meajor_format")}
    if profile.get("meajor"):
        slim_profile["meajor"] = {k: profile["meajor"].get(k) for k in ("rows", "label_counts", "source_counts", "label_by_source",
                                                                       "license", "label_semantics", "anonymisation",
                                                                       "dropped_invalid_label_or_empty_body", "language_top", "body_length")}
    slim_profile["supplementary"] = {k: {kk: v.get(kk) for kk in ("rows", "role", "label_semantics", "label_counts", "license", "status")}
                                     for k, v in (profile.get("supplementary") or {}).items()}
    return {"model": state.model.info(), "candidates": meta.get("candidates", []),
            "evaluation": _read_json(settings.model_dir / "evaluation_latest.json"), "training_runs": runs[-10:],
            "dataset_profile": slim_profile, "download_manifest": profile.get("download_manifest", []),
            "feature_usage": {
                "ml_trained": ["subject + visible body text → TF-IDF (word 1-2gram + char 3-5gram) → linear SVM (sigmoid-calibrated)"],
                "deterministic_rules": ["tactics & requested actions", "sender/Reply-To/lookalike/profile identity checks",
                                        "authentication-result parsing (unverified unless trusted authserv-id)", "URL lexical checks",
                                        "attachment static triage", "hidden-content & AI-assistant instruction detection",
                                        "Unicode evasion normalisation", "thread consistency", "campaign correlation"],
                "not_trained_on": "headers, attachments, hidden HTML and prompt-injection content are NOT model features; "
                                  "the corpora do not contain suitable labels for them."},
            "commands": {"download": "python scripts/download_datasets.py --supplementary",
                         "preprocess": "python scripts/preprocess_dataset.py", "train": "python scripts/train_model.py",
                         "evaluate": "python scripts/evaluate_model.py", "benchmark_fixtures": "python scripts/build_benchmark.py"}}


@router.get("/dashboard/summary")
def dashboard():
    db = state.db
    total = db.scalar("SELECT COUNT(*) FROM analyses") or 0
    verdicts = {r["verdict"]: r["n"] for r in db.all("SELECT verdict, COUNT(*) n FROM analyses GROUP BY verdict")}
    labels = {r["data_label"]: r["n"] for r in db.all("SELECT data_label, COUNT(*) n FROM analyses GROUP BY data_label")}
    sources = {r["input_source"]: r["n"] for r in db.all("SELECT input_source, COUNT(*) n FROM analyses GROUP BY input_source")}
    hist = [0] * 10
    for r in db.all("SELECT risk_score FROM analyses"):
        hist[min(int((r["risk_score"] or 0) // 10), 9)] += 1
    cases = {r["status"]: r["n"] for r in db.all("SELECT status, COUNT(*) n FROM cases GROUP BY status")}
    alerts = db.all("SELECT c.id AS case_id, c.priority, c.priority_score, c.status, a.id, a.subject, a.from_addr, a.verdict, "
                    "a.verdict_label, a.risk_score, a.created_at, a.data_label FROM cases c JOIN analyses a ON a.id=c.analysis_id "
                    "WHERE c.status != 'resolved' ORDER BY c.priority, c.priority_score DESC LIMIT 8")
    camps = db.all("SELECT id, label, severity, severity_score, member_count, low_and_slow, last_seen FROM campaigns "
                   "ORDER BY severity_score DESC LIMIT 6")
    q = ",".join("?" * len(COMMON_DOMAINS))
    top_inds = db.all(f"SELECT i.id, i.type, i.display_value, i.reputation, COUNT(DISTINCT ai.analysis_id) AS messages FROM indicators i "
                      f"JOIN analysis_indicators ai ON ai.indicator_id=i.id WHERE i.type IN ('url','domain','sha256','reply_to_address') "
                      f"AND i.value NOT IN ({q}) GROUP BY i.id HAVING messages >= 2 ORDER BY messages DESC LIMIT 8", sorted(COMMON_DOMAINS))
    in_camp = db.scalar("SELECT COUNT(DISTINCT analysis_id) FROM campaign_members") or 0
    n_camp = db.scalar("SELECT COUNT(*) FROM campaigns") or 0
    resolved = db.all("SELECT created_at, updated_at FROM cases WHERE status='resolved'")
    from datetime import datetime
    durs = []
    for r in resolved:
        try:
            durs.append((datetime.fromisoformat(r["updated_at"]) - datetime.fromisoformat(r["created_at"])).total_seconds() / 60)
        except Exception:
            pass
    fb = {r["label"]: r["n"] for r in db.all("SELECT label, COUNT(*) n FROM feedback GROUP BY label")}
    headers_share = db.scalar("SELECT AVG(CASE WHEN json_extract(parsed_json,'$.headers_present') THEN 1.0 ELSE 0 END) FROM analyses")
    last_eval = db.one("SELECT id, status, finished_at, metrics_json FROM evaluation_runs WHERE status='completed' "
                       "ORDER BY finished_at DESC LIMIT 1")
    bench = None
    if last_eval:
        m = last_eval["metrics_json"] or {}
        bench = {"id": last_eval["id"], "finished_at": last_eval["finished_at"], "overall": m.get("overall"),
                 "counts": m.get("counts"), "data_label": m.get("data_label")}
    return {"totals": {"analyses": total, "high_risk": verdicts.get("LIKELY_PHISHING", 0) + verdicts.get("AI_INJECTION_SUSPECTED", 0),
                       "needs_review": verdicts.get("SUSPICIOUS_REVIEW", 0), "open_cases": sum(v for k, v in cases.items() if k != "resolved"),
                       "campaigns": n_camp, "low_and_slow": db.scalar("SELECT COUNT(*) FROM campaigns WHERE low_and_slow=1") or 0},
            "verdicts": verdicts, "data_labels": labels, "sources": sources, "risk_histogram": hist, "case_states": cases,
            "alerts": alerts, "campaigns": camps, "top_indicators": top_inds,
            "triage": {"queue_volume": sum(v for k, v in cases.items() if k != "resolved"),
                       "messages_in_campaigns": in_camp, "campaign_clusters": n_camp,
                       "duplicate_alert_collapse": (in_camp - n_camp) if n_camp else 0,
                       "median_minutes_to_resolve": round(float(np.median(durs)), 1) if durs else None,
                       "resolved_cases": len(durs), "feedback": fb},
            "coverage": {"headers_present_share": round(headers_share or 0, 3)},
            "model": {"status": state.model.status, "version": state.model.version}, "benchmark": bench}
