"""Analysis endpoints: analyze, batch, list, detail, delete, re-score, report export."""
from __future__ import annotations

import asyncio
import csv
import io
import json
import re
import uuid

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse, Response

from ..config import settings
from ..email_processing.parser import EmailParseError
from ..services.audit import audit
from ..state import state

router = APIRouter(prefix="/api/v1", tags=["analysis"])
ALLOWED_UPLOAD = {".eml", ".txt", ".msg"}


async def _read_limited(f: UploadFile) -> bytes:
    data = await f.read(settings.max_email_bytes + 1)
    if len(data) > settings.max_email_bytes:
        raise HTTPException(413, f"{f.filename}: file exceeds {settings.max_email_bytes} bytes")
    return data


def _ext(name: str) -> str:
    m = re.search(r"(\.[A-Za-z0-9]{1,5})$", name or "")
    return m.group(1).lower() if m else ""


async def _run(raw: bytes, source: str, subject=None, sender=None, data_label="user", batch_id=None) -> dict:
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, lambda: state.engine.analyze(raw, source, subject, sender, data_label, batch_id)),
            timeout=settings.analysis_timeout_s)
    except asyncio.TimeoutError:
        audit(state.db, "analysis.timeout", "system", "analysis", "-", "failed", f"source={source} bytes={len(raw)}")
        raise HTTPException(504, f"analysis exceeded {settings.analysis_timeout_s}s; no verdict was produced")


@router.post("/analyze")
async def analyze(file: UploadFile | None = File(None), text: str | None = Form(None),
                  subject: str | None = Form(None), sender: str | None = Form(None)):
    if file is not None and file.filename:
        ext = _ext(file.filename)
        if ext == ".msg":
            raise HTTPException(415, ".msg (Outlook) parsing is not supported in this build; export the message as .eml")
        if ext not in ALLOWED_UPLOAD:
            raise HTTPException(415, f"unsupported file type '{ext or 'none'}'; upload .eml or .txt")
        raw = await _read_limited(file)
        source = "eml" if ext == ".eml" else "paste"
    elif text and text.strip():
        raw = text.encode("utf-8")
        if len(raw) > settings.max_email_bytes:
            raise HTTPException(413, f"text exceeds {settings.max_email_bytes} bytes")
        source = "paste"
    else:
        raise HTTPException(422, "provide an .eml file or paste email text")
    try:
        res = await _run(raw, source, subject, sender)
    except EmailParseError as exc:
        raise HTTPException(422, f"could not parse input: {exc}")
    return detail(res["id"])


@router.post("/analyze/batch")
async def analyze_batch(files: list[UploadFile] = File(...)):
    items: list[tuple[str, bytes, str, str | None, str | None]] = []
    for f in files:
        ext = _ext(f.filename or "")
        data = await _read_limited(f)
        if ext == ".csv":
            try:
                reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig", errors="replace")))
                cols = {c.lower(): c for c in (reader.fieldnames or [])}
                if "body" not in cols:
                    items.append((f.filename, b"", "error:CSV needs a 'body' column (optional: subject, sender)", None, None))
                    continue
                for i, row in enumerate(reader):
                    items.append((f"{f.filename}#{i + 1}", (row.get(cols["body"]) or "").encode(), "paste",
                                  row.get(cols.get("subject", ""), None), row.get(cols.get("sender", ""), None)))
            except Exception as exc:
                items.append((f.filename, b"", f"error:CSV parse failed ({type(exc).__name__})", None, None))
        elif ext in (".eml", ".txt"):
            items.append((f.filename, data, "eml" if ext == ".eml" else "paste", None, None))
        else:
            items.append((f.filename or "?", b"", f"error:unsupported file type '{ext}'", None, None))
    if len(items) > settings.max_batch_items:
        raise HTTPException(413, f"batch has {len(items)} messages; limit is {settings.max_batch_items}")
    batch_id = "B-" + uuid.uuid4().hex[:8].upper()
    results = []
    for name, raw, src, subj, sender in items:
        if src.startswith("error:"):
            results.append({"name": name, "status": "failed", "error": src[6:]})
            continue
        try:
            r = await _run(raw, src, subj, sender, batch_id=batch_id)
            results.append({"name": name, "status": "ok", "id": r["id"], "verdict": r["verdict"], "risk_score": r["risk_score"]})
        except HTTPException as exc:
            results.append({"name": name, "status": "failed", "error": exc.detail})
        except EmailParseError as exc:
            results.append({"name": name, "status": "failed", "error": str(exc)})
    ok = [r for r in results if r["status"] == "ok"]
    summary = {"total": len(results), "ok": len(ok), "failed": len(results) - len(ok),
               "verdicts": {v: sum(1 for r in ok if r["verdict"] == v) for v in {r["verdict"] for r in ok}}}
    audit(state.db, "batch.analyzed", "local-analyst", "batch", batch_id, "ok", json.dumps(summary))
    return {"batch_id": batch_id, "summary": summary, "results": results}


@router.get("/analyses")
def list_analyses(verdict: str | None = None, q: str | None = None, data_label: str | None = None,
                  limit: int = Query(50, le=500), offset: int = 0):
    where, params = [], []
    if verdict:
        where.append("verdict = ?")
        params.append(verdict)
    if data_label:
        where.append("data_label = ?")
        params.append(data_label)
    if q:
        where.append("(subject LIKE ? OR from_addr LIKE ? OR id LIKE ?)")
        params += [f"%{q}%"] * 3
    w = ("WHERE " + " AND ".join(where)) if where else ""
    rows = state.db.all(f"SELECT id, created_at, input_source, data_label, subject, from_addr, verdict, verdict_label, risk_score, "
                        f"priority, priority_score, local_state, model_version, batch_id FROM analyses {w} "
                        f"ORDER BY created_at DESC LIMIT ? OFFSET ?", [*params, limit, offset])
    total = state.db.scalar(f"SELECT COUNT(*) FROM analyses {w}", params)
    return {"total": total, "items": rows}


def detail(aid: str) -> dict:
    a = state.db.one("SELECT * FROM analyses WHERE id=?", (aid,))
    if not a:
        raise HTTPException(404, "analysis not found")
    findings = state.db.all("SELECT * FROM findings WHERE analysis_id=? ORDER BY id", (aid,))
    for f in findings:
        f["span"] = f.pop("span_json")
        f["tags"] = f.pop("tags_json")
    case = state.db.one("SELECT * FROM cases WHERE analysis_id=?", (aid,))
    camp = state.db.all("SELECT c.id, c.label, c.severity, c.member_count FROM campaign_members m JOIN campaigns c "
                        "ON c.id=m.campaign_id WHERE m.analysis_id=?", (aid,))
    edges = state.db.all("SELECT * FROM campaign_edges WHERE src=? OR dst=? ORDER BY strength DESC LIMIT 50", (aid, aid))
    for e in edges:
        e["other"] = e["dst"] if e["src"] == aid else e["src"]
    inds = state.db.all("SELECT i.id, i.type, i.display_value, i.reputation, i.reputation_source, i.sightings, ai.location "
                        "FROM analysis_indicators ai JOIN indicators i ON i.id=ai.indicator_id WHERE ai.analysis_id=?", (aid,))
    versions = state.db.all("SELECT * FROM analysis_versions WHERE analysis_id=? ORDER BY id", (aid,))
    fb = state.db.all("SELECT * FROM feedback WHERE analysis_id=? ORDER BY id", (aid,))
    raw_retained = bool(state.db.scalar("SELECT 1 FROM raw_inputs WHERE analysis_id=?", (aid,)))
    expl = a.pop("explanation_json") or {}
    return {
        "id": a["id"], "created_at": a["created_at"], "input_source": a["input_source"], "data_label": a["data_label"],
        "batch_id": a["batch_id"], "parsed": a["parsed_json"], "verdict": a["verdict"], "verdict_label": a["verdict_label"],
        "risk_score": a["risk_score"], "score_semantics": "0-100 policy risk score (not a probability)",
        "decision": a["decision_json"], "uncertainty": a["uncertainty_json"], "impact": a["impact_json"],
        "strengths": a["strengths_json"], "model": a["model_json"], "tactics": a["tactics_json"], "actions": a["actions_json"],
        "findings": findings, "reconstruction": a["reconstruction_json"], "explanation": expl.get("explanation"),
        "recommendations": expl.get("recommendations", []), "threat_intel": expl.get("threat_intel"),
        "stage_status": a["stage_status_json"], "versions": {"model": a["model_version"], "rules": a["rules_version"],
                                                              "fusion": a["fusion_version"]},
        "latency_ms": a["latency_ms"], "body_text": a["body_text"], "preview": a["preview"], "local_state": a["local_state"],
        "original": {"verdict": a["original_verdict"], "risk_score": a["original_risk_score"]},
        "case": case, "campaigns": camp, "related_edges": edges, "indicators": inds, "history": versions, "feedback": fb,
        "raw_retained": raw_retained,
    }


@router.get("/analyses/{aid}")
def get_analysis(aid: str):
    return detail(aid)


@router.delete("/analyses/{aid}")
def delete_analysis(aid: str):
    if not state.db.one("SELECT id FROM analyses WHERE id=?", (aid,)):
        raise HTTPException(404, "analysis not found")
    with state.db.transaction() as c:
        for sql in ("DELETE FROM findings WHERE analysis_id=?", "DELETE FROM raw_inputs WHERE analysis_id=?",
                    "DELETE FROM analysis_indicators WHERE analysis_id=?", "DELETE FROM cases WHERE analysis_id=?",
                    "DELETE FROM feedback WHERE analysis_id=?", "DELETE FROM analysis_versions WHERE analysis_id=?",
                    "DELETE FROM campaign_members WHERE analysis_id=?", "DELETE FROM campaign_edges WHERE src=? OR dst=?",
                    "DELETE FROM analyses WHERE id=?"):
            c.execute(sql, (aid, aid) if sql.count("?") == 2 else (aid,))
    state.engine.campaigns.rebuild()
    audit(state.db, "analysis.deleted", "local-analyst", "analysis", aid, "ok", "analysis, evidence and retained raw content deleted")
    return {"deleted": aid}


@router.post("/analyses/{aid}/rescore")
async def rescore(aid: str):
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, lambda: state.engine.rescore(aid, "manual re-score"))
    if res is None:
        raise HTTPException(404, "analysis not found")
    return res


@router.get("/analyses/{aid}/report")
def report(aid: str, format: str = Query("json", pattern="^(json|md|csv)$")):
    d = detail(aid)
    d.pop("body_text", None)  # reports carry evidence excerpts, not the full message body
    audit(state.db, "report.exported", "local-analyst", "analysis", aid, "ok", f"format={format}")
    if format == "json":
        return Response(json.dumps(d, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{aid}-report.json"'})
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["analysis_id", "finding_id", "category", "component", "severity", "status", "confidence", "method",
                    "version", "source_location", "observed_value", "explanation"])
        for f in d["findings"]:
            w.writerow([aid, f["finding_id"], f["category"], f["component"], f["severity"], f["status"], f["confidence"],
                        f["method"], f["version"], f["source_location"], f["observed_value"], f["explanation"]])
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{aid}-findings.csv"'})
    return PlainTextResponse(markdown_report(d), headers={"Content-Disposition": f'attachment; filename="{aid}-report.md"'})


def markdown_report(d: dict) -> str:
    p = d["parsed"] or {}
    rec = d["reconstruction"] or {}
    lines = [f"# PHISHDNA AI analyst report — {d['id']}", "",
             f"- **Verdict:** {d['verdict_label']} (`{d['verdict']}`)",
             f"- **Risk score:** {d['risk_score']} / 100 (policy risk score, not a probability)",
             f"- **Uncertainty:** {d['uncertainty']['level']} — {'; '.join(d['uncertainty']['reasons']) or 'none noted'}",
             f"- **Potential impact / priority:** {d['impact']['potential_impact']} / {d['impact']['priority']}",
             f"- **Data label:** {d['data_label']} · **Source:** {d['input_source']} · **Analysed:** {d['created_at']}",
             f"- **Versions:** model `{d['versions']['model']}`, rules `{d['versions']['rules']}`, fusion `{d['versions']['fusion']}`",
             f"- **Local state:** {d['local_state']} (local record only — no mailbox action was taken)", "",
             "## Message", f"- From: {p.get('from_display', '')} <{p.get('from_addr', '')}>",
             f"- Reply-To: {p.get('reply_to_addr') or '—'}", f"- Subject: {p.get('subject', '')}", "",
             "## Decision", *[f"- {r}" for r in d["decision"]["decision_reasons"]], "",
             "## Attack reconstruction", rec.get("narrative", ""), "", f"_{rec.get('caveat', '')}_", "",
             "## Evidence", "| ID | Status | Severity | Finding | Location | Observed | Method |", "|---|---|---|---|---|---|---|"]
    for f in d["findings"]:
        obs = (f["observed_value"] or "").replace("|", "\\|").replace("\n", " ")[:120]
        lines.append(f"| {f['finding_id']} | {f['status']} | {f['severity']} | {f['title']} | {f['source_location']} | {obs} | "
                     f"{f['method']} {f['version']} |")
    lines += ["", "## Recommended response", *[f"- {r['text']}" for r in d["recommendations"]], "",
              "## MITRE mapping", *([f"- {a['id']} — {a['name']}" for a in rec.get("attack_mapping", [])] or ["- none justified"]),
              "", "## Stage status", *[f"- {k}: {v.get('status')} {v.get('detail', '')}" for k, v in (d["stage_status"] or {}).items()],
              "", "## Indicators", *[f"- {i['type']}: {i['display_value']} (reputation: {i['reputation'] or 'unknown'})" for i in d["indicators"]]]
    if d["case"]:
        lines += ["", "## Case", f"- {d['case']['id']}: status {d['case']['status']}, priority {d['case']['priority']}, "
                                  f"assignee {d['case']['assignee'] or '—'}"]
    return "\n".join(lines) + "\n"
