"""Analyst queue, case actions, feedback/review queue and audit trail.

All response actions (quarantine, release, banner, report) change LOCAL records only. Responses say
"local record updated" — never that a mailbox was changed.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..services.audit import audit
from ..services.indicators import COMMON_DOMAINS
from ..state import state

router = APIRouter(prefix="/api/v1", tags=["cases"])
STATUSES = {"open", "in_review", "escalated", "resolved"}
FEEDBACK = {"confirmed_phishing", "benign", "unresolved", "false_positive"}
ACTIONS = {"report_phishing", "mark_benign", "escalate", "resolve", "reopen", "quarantine", "release", "banner", "assign"}
AWARENESS = {
    "urgency": "Urgency is used to stop you from checking. Real deadlines survive a 5-minute verification call.",
    "authority": "Messages that lean on a title (CEO, IT, tax office) want you to skip normal checks. Verify via the directory.",
    "secrecy": "Requests to keep a payment or data transfer secret bypass the controls designed to catch fraud.",
    "financial_diversion": "Bank-detail changes should always be confirmed on a phone number you already have on file.",
    "credential_harvesting": "Type the service address yourself instead of following a sign-in link from email.",
    "policy_bypass": "'Don't call me, I'm in a meeting' is a classic way to block verification.",
    "fear": "Threats of account closure create panic; check the account directly, not through the email.",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaseUpdate(BaseModel):
    action: str | None = Field(None, description="report_phishing|mark_benign|escalate|resolve|reopen|quarantine|release|banner|assign")
    status: str | None = None
    assignee: str | None = Field(None, max_length=80)
    note: str | None = Field(None, max_length=2000)
    feedback_label: str | None = None
    reviewer: str | None = Field("local-analyst", max_length=80)
    confirm: bool = False


@router.get("/cases")
def list_cases(status: str | None = None, priority: str | None = None, limit: int = Query(100, le=500)):
    where, params = [], []
    if status:
        where.append("c.status=?")
        params.append(status)
    if priority:
        where.append("c.priority=?")
        params.append(priority)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    rows = state.db.all(
        f"SELECT c.*, a.subject, a.from_addr, a.verdict, a.verdict_label, a.risk_score, a.local_state, a.data_label, "
        f"a.impact_json, (SELECT COUNT(*) FROM campaign_members m WHERE m.analysis_id=a.id) AS in_campaigns "
        f"FROM cases c JOIN analyses a ON a.id=c.analysis_id {w} "
        f"ORDER BY CASE c.status WHEN 'resolved' THEN 1 ELSE 0 END, c.priority, c.priority_score DESC, c.created_at DESC LIMIT ?",
        [*params, limit])
    counts = {r["status"]: r["n"] for r in state.db.all("SELECT status, COUNT(*) n FROM cases GROUP BY status")}
    return {"items": rows, "counts": counts}


@router.get("/cases/{cid}")
def get_case(cid: str):
    c = state.db.one("SELECT * FROM cases WHERE id=?", (cid,))
    if not c:
        raise HTTPException(404, "case not found")
    c["audit"] = state.db.all("SELECT * FROM audit_events WHERE target_id IN (?, ?) ORDER BY id DESC LIMIT 100",
                              (cid, c["analysis_id"]))
    return c


@router.patch("/cases/{cid}")
def update_case(cid: str, body: CaseUpdate):
    c = state.db.one("SELECT * FROM cases WHERE id=?", (cid,))
    if not c:
        raise HTTPException(404, "case not found")
    a = state.db.one("SELECT id, verdict, risk_score, model_version, tactics_json FROM analyses WHERE id=?", (c["analysis_id"],))
    fields: dict = {"updated_at": now()}
    msgs: list[str] = []
    notes = c["notes_json"] or []
    actor = body.reviewer or "local-analyst"
    if body.action and body.action not in ACTIONS:
        raise HTTPException(422, f"unknown action; allowed: {sorted(ACTIONS)}")
    if body.status:
        if body.status not in STATUSES:
            raise HTTPException(422, f"status must be one of {sorted(STATUSES)}")
        fields["status"] = body.status
        msgs.append(f"status → {body.status}")
    if body.assignee is not None:
        fields["assignee"] = body.assignee or None
        msgs.append(f"assigned to {body.assignee or 'nobody'}")
    label = body.feedback_label
    act = body.action
    if act == "report_phishing":
        label = label or "confirmed_phishing"
        fields["status"] = "in_review" if c["status"] == "open" else c["status"]
    elif act == "mark_benign":
        label = label or ("false_positive" if a["verdict"] != "NO_STRONG_INDICATORS" else "benign")
        fields["status"] = "resolved"
        fields["resolution"] = "benign"
    elif act == "escalate":
        fields["status"] = "escalated"
        fields["priority"] = "P1"
    elif act == "resolve":
        fields["status"] = "resolved"
        fields["resolution"] = label or "resolved"
    elif act == "reopen":
        fields["status"] = "open"
        fields["resolution"] = None
    elif act in ("quarantine", "release", "banner"):
        if act == "quarantine" and not body.confirm:
            raise HTTPException(409, "quarantine is a high-impact action: resend with confirm=true after review")
        new_state = {"quarantine": "quarantined (local)", "release": "released (local)", "banner": "warning banner (local)"}[act]
        state.db.update("analyses", "id", a["id"], {"local_state": new_state})
        msgs.append(f"local record updated: {new_state} — sandbox action, no mailbox was changed")
    if label:
        if label not in FEEDBACK:
            raise HTTPException(422, f"feedback_label must be one of {sorted(FEEDBACK)}")
        state.db.insert("feedback", {"analysis_id": a["id"], "case_id": cid, "label": label, "notes": body.note or "",
                                     "reviewer": actor, "created_at": now(), "original_verdict": a["verdict"],
                                     "original_risk_score": a["risk_score"], "model_version": a["model_version"]})
        msgs.append(f"analyst feedback recorded: {label} (original prediction kept unchanged)")
        if label == "confirmed_phishing":
            n = _propose_iocs(a["id"], actor)
            msgs.append(f"{n} indicator(s) added to the IOC review queue (pending review, not yet trusted)")
    if body.note:
        notes.append({"ts": now(), "author": actor, "text": body.note})
        fields["notes_json"] = notes
    state.db.update("cases", "id", cid, fields)
    audit(state.db, f"case.{act or 'update'}", actor, "case", cid, "ok", "; ".join(msgs) or json.dumps({k: v for k, v in fields.items() if k != 'notes_json'}))
    out = get_case(cid)
    out["messages"] = msgs
    tactics = list((a["tactics_json"] or {}).keys())
    if act in ("report_phishing",) and tactics:
        out["awareness"] = [{"tactic": t, "tip": AWARENESS[t]} for t in tactics if t in AWARENESS][:3]
    return out


def _propose_iocs(aid: str, actor: str) -> int:
    rows = state.db.all("SELECT i.* FROM analysis_indicators ai JOIN indicators i ON i.id=ai.indicator_id WHERE ai.analysis_id=? "
                        "AND i.type IN ('url','domain','sha256','reply_to_address','sender_address')", (aid,))
    n = 0
    for r in rows:
        if r["type"] == "domain" and r["value"] in COMMON_DOMAINS:
            continue
        if r["review_status"] in ("approved",):
            continue
        state.db.update("indicators", "id", r["id"], {"reputation": "malicious", "reputation_source": f"analyst report ({actor})",
                                                      "review_status": "pending_review", "reputation_checked_at": now(),
                                                      "expires_at": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()})
        state.db.insert("indicator_history", {"indicator_id": r["id"], "ts": now(), "old_reputation": r["reputation"],
                                              "new_reputation": "malicious (pending review)", "source": "analyst report",
                                              "actor": actor, "note": f"from {aid}"})
        n += 1
    return n


@router.get("/feedback")
def list_feedback(format: str = Query("json", pattern="^(json|csv)$")):
    rows = state.db.all("SELECT f.*, a.subject FROM feedback f LEFT JOIN analyses a ON a.id=f.analysis_id ORDER BY f.id DESC")
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["analysis_id", "label", "original_verdict", "original_risk_score", "model_version", "reviewer", "created_at",
                    "retraining_status", "notes"])
        for r in rows:
            w.writerow([r["analysis_id"], r["label"], r["original_verdict"], r["original_risk_score"], r["model_version"],
                        r["reviewer"], r["created_at"], r["retraining_status"], r["notes"]])
        return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="review_queue.csv"'})
    disagreements = sum(1 for r in rows if (r["label"] in ("benign", "false_positive") and r["original_verdict"] != "NO_STRONG_INDICATORS")
                        or (r["label"] == "confirmed_phishing" and r["original_verdict"] == "NO_STRONG_INDICATORS"))
    return {"items": rows, "summary": {"total": len(rows), "model_disagreements": disagreements,
                                       "note": "Feedback is queued for future retraining review; the model is never retrained silently."}}


@router.get("/audit")
def list_audit(target: str | None = None, limit: int = Query(200, le=1000)):
    if target:
        return state.db.all("SELECT * FROM audit_events WHERE target_id=? ORDER BY id DESC LIMIT ?", (target, limit))
    return state.db.all("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,))
