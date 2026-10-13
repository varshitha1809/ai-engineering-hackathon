"""Campaigns, relationship graph, IOC store (with re-score) and sender/vendor profiles."""
from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..email_processing.urls import normalise_url
from ..services.audit import audit
from ..state import state

router = APIRouter(prefix="/api/v1", tags=["intelligence"])


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------ campaigns
@router.get("/campaigns")
def list_campaigns(severity: str | None = None, low_and_slow: bool | None = None):
    where, params = [], []
    if severity:
        where.append("severity=?")
        params.append(severity)
    if low_and_slow is not None:
        where.append("low_and_slow=?")
        params.append(int(low_and_slow))
    w = ("WHERE " + " AND ".join(where)) if where else ""
    items = state.db.all(f"SELECT * FROM campaigns {w} ORDER BY severity_score DESC", params)
    weak = state.db.scalar("SELECT COUNT(*) FROM campaign_edges WHERE strength < 0.5")
    return {"items": items, "weak_edges_not_clustered": weak,
            "rule": "Clusters are connected components over relationships with strength ≥ 0.5; each relationship cites its evidence."}


@router.get("/campaigns/{cid}")
def get_campaign(cid: str):
    c = state.db.one("SELECT * FROM campaigns WHERE id=?", (cid,))
    if not c:
        raise HTTPException(404, "campaign not found")
    members = state.db.all("SELECT a.id, a.created_at, a.email_date, a.subject, a.from_addr, a.reply_to_addr, a.verdict, "
                           "a.verdict_label, a.risk_score, a.priority, a.data_label, a.actions_json FROM campaign_members m "
                           "JOIN analyses a ON a.id=m.analysis_id WHERE m.campaign_id=? ORDER BY COALESCE(a.email_date, a.created_at)",
                           (cid,))
    edges = state.db.all("SELECT * FROM campaign_edges WHERE campaign_id=? ORDER BY strength DESC", (cid,))
    ids = [m["id"] for m in members]
    q = ",".join("?" * len(ids))
    inds = state.db.all(f"SELECT i.type, i.display_value, i.reputation, i.reputation_source, COUNT(DISTINCT ai.analysis_id) AS members "
                        f"FROM analysis_indicators ai JOIN indicators i ON i.id=ai.indicator_id WHERE ai.analysis_id IN ({q}) "
                        f"GROUP BY i.id HAVING members >= 2 ORDER BY members DESC", ids) if ids else []
    return {**c, "members": members, "edges": edges, "shared_indicators": inds}


@router.get("/campaigns/{cid}/export")
def export_campaign(cid: str, format: str = Query("json", pattern="^(json|csv|stix)$")):
    c = get_campaign(cid)
    audit(state.db, "campaign.exported", "local-analyst", "campaign", cid, "ok", f"format={format} (local file, not shared)")
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["campaign_id", "edge_type", "strength", "strength_label", "src", "dst", "explanation", "evidence"])
        for e in c["edges"]:
            w.writerow([cid, e["edge_type"], e["strength"], e["strength_label"], e["src"], e["dst"], e["explanation"],
                        json.dumps(e["evidence_json"])])
        return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{cid}.csv"'})
    if format == "stix":
        objs = [{"type": "identity", "spec_version": "2.1", "id": f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'phishdna-local')}",
                 "created": now(), "modified": now(), "name": "PHISHDNA AI (local instance)", "identity_class": "system"}]
        camp_id = f"campaign--{uuid.uuid5(uuid.NAMESPACE_URL, cid)}"
        objs.append({"type": "campaign", "spec_version": "2.1", "id": camp_id, "created": c["created_at"], "modified": c["updated_at"],
                     "name": c["label"], "description": f"Locally correlated cluster of {c['member_count']} messages. "
                     "Relationships are evidence of relatedness, not attribution.", "created_by_ref": objs[0]["id"]})
        for i in c["shared_indicators"]:
            if i["type"] in ("url", "domain") and "(masked)" not in i["display_value"]:
                patt = f"[url:value = '{i['display_value']}']" if i["type"] == "url" else f"[domain-name:value = '{i['display_value']}']"
                iid = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, i['display_value'])}"
                objs.append({"type": "indicator", "spec_version": "2.1", "id": iid, "created": now(), "modified": now(),
                             "pattern": patt.replace("\\", "\\\\"), "pattern_type": "stix", "valid_from": now(),
                             "description": f"shared by {i['members']} messages; reputation: {i['reputation'] or 'unknown'}"})
                objs.append({"type": "relationship", "spec_version": "2.1", "id": f"relationship--{uuid.uuid4()}", "created": now(),
                             "modified": now(), "relationship_type": "indicates", "source_ref": iid, "target_ref": camp_id})
        bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}
        return Response(json.dumps(bundle, indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{cid}.stix.json"'})
    return Response(json.dumps(c, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{cid}.json"'})


@router.get("/graph")
def graph(min_strength: float = 0.0, campaign: str | None = None, limit: int = Query(400, le=2000)):
    if campaign:
        edges = state.db.all("SELECT * FROM campaign_edges WHERE campaign_id=? AND strength>=?", (campaign, min_strength))
    else:
        edges = state.db.all("SELECT * FROM campaign_edges WHERE strength>=? ORDER BY strength DESC LIMIT ?", (min_strength, limit))
    ids = sorted({e["src"] for e in edges} | {e["dst"] for e in edges})
    nodes = []
    if ids:
        q = ",".join("?" * len(ids))
        nodes = state.db.all(f"SELECT a.id, a.subject, a.from_addr, a.verdict, a.risk_score, a.created_at, a.email_date, "
                             f"(SELECT campaign_id FROM campaign_members m WHERE m.analysis_id=a.id LIMIT 1) AS campaign_id "
                             f"FROM analyses a WHERE a.id IN ({q})", ids)
    return {"nodes": nodes, "edges": edges}


# ------------------------------------------------------------------ indicators / local threat intelligence
class IndicatorIn(BaseModel):
    type: str = Field(..., pattern="^(url|domain|sha256|sender_address|reply_to_address|sender_domain)$")
    value: str = Field(..., min_length=3, max_length=2000)
    reputation: str = Field("malicious", pattern="^(malicious|suspicious|clean|unknown)$")
    source: str = Field("analyst (local)", max_length=120)
    expires_days: int = Field(90, ge=1, le=3650)
    notes: str = Field("", max_length=500)
    rescore: bool = True


class IndicatorPatch(BaseModel):
    reputation: str | None = Field(None, pattern="^(malicious|suspicious|clean|unknown)$")
    review_status: str | None = Field(None, pattern="^(approved|rejected|pending_review|none)$")
    rescore: bool = True


def _normal_value(t: str, v: str) -> str:
    v = v.strip()
    if t == "url":
        return normalise_url(v).normalised.lower()
    return v.lower()


@router.get("/indicators")
def list_indicators(type: str | None = None, q: str | None = None, review_status: str | None = None,
                    limit: int = Query(200, le=1000)):
    where, params = [], []
    if type:
        where.append("type=?")
        params.append(type)
    if review_status:
        where.append("review_status=?")
        params.append(review_status)
    if q:
        where.append("display_value LIKE ?")
        params.append(f"%{q}%")
    w = ("WHERE " + " AND ".join(where)) if where else ""
    items = state.db.all(f"SELECT i.*, (SELECT COUNT(DISTINCT analysis_id) FROM analysis_indicators ai WHERE ai.indicator_id=i.id) "
                         f"AS messages FROM indicators i {w} ORDER BY messages DESC, sightings DESC LIMIT ?", [*params, limit])
    return {"items": items, "providers": state.engine.providers_status()}


def _affected_and_rescore(ind_id: int, reason: str) -> list[dict]:
    aids = [r["analysis_id"] for r in state.db.all("SELECT DISTINCT analysis_id FROM analysis_indicators WHERE indicator_id=?", (ind_id,))]
    return [r for r in (state.engine.rescore(a, reason) for a in aids[:100]) if r]


@router.post("/indicators")
def add_indicator(body: IndicatorIn):
    val = _normal_value(body.type, body.value)
    exp = (datetime.now(timezone.utc) + timedelta(days=body.expires_days)).isoformat()
    old = state.db.one("SELECT * FROM indicators WHERE type=? AND value=?", (body.type, val))
    if old:
        state.db.update("indicators", "id", old["id"], {"reputation": body.reputation, "reputation_source": body.source,
                                                        "reputation_checked_at": now(), "review_status": "approved",
                                                        "expires_at": exp, "notes": body.notes})
        iid = old["id"]
    else:
        iid = state.db.insert("indicators", {"type": body.type, "value": val, "display_value": body.value.strip()[:300],
                                             "first_seen_local": now(), "last_seen_local": now(), "sightings": 0,
                                             "reputation": body.reputation, "reputation_source": body.source,
                                             "reputation_checked_at": now(), "review_status": "approved", "expires_at": exp,
                                             "notes": body.notes})
    state.db.insert("indicator_history", {"indicator_id": iid, "ts": now(), "old_reputation": old["reputation"] if old else None,
                                          "new_reputation": body.reputation, "source": body.source, "actor": "local-analyst",
                                          "note": body.notes})
    audit(state.db, "indicator.set", "local-analyst", "indicator", str(iid), "ok", f"{body.type} → {body.reputation} ({body.source})")
    changes = _affected_and_rescore(iid, f"indicator {iid} reputation set to {body.reputation}") if body.rescore else []
    return {"indicator": state.db.one("SELECT * FROM indicators WHERE id=?", (iid,)), "rescored": changes}


@router.patch("/indicators/{iid}")
def patch_indicator(iid: int, body: IndicatorPatch):
    old = state.db.one("SELECT * FROM indicators WHERE id=?", (iid,))
    if not old:
        raise HTTPException(404, "indicator not found")
    fields = {"reputation_checked_at": now()}
    if body.reputation:
        fields["reputation"] = body.reputation
    if body.review_status:
        fields["review_status"] = body.review_status
        if body.review_status == "rejected":
            fields["reputation"] = "unknown"
    state.db.update("indicators", "id", iid, fields)
    state.db.insert("indicator_history", {"indicator_id": iid, "ts": now(), "old_reputation": f"{old['reputation']} ({old['review_status']})",
                                          "new_reputation": f"{fields.get('reputation', old['reputation'])} ({fields.get('review_status', old['review_status'])})",
                                          "source": "review", "actor": "local-analyst", "note": ""})
    audit(state.db, "indicator.reviewed", "local-analyst", "indicator", str(iid), "ok", json.dumps(fields))
    changes = _affected_and_rescore(iid, f"indicator {iid} review: {json.dumps(fields)}") if body.rescore else []
    return {"indicator": state.db.one("SELECT * FROM indicators WHERE id=?", (iid,)), "rescored": changes}


@router.get("/indicators/{iid}/history")
def indicator_history(iid: int):
    return state.db.all("SELECT * FROM indicator_history WHERE indicator_id=? ORDER BY id", (iid,))


# ------------------------------------------------------------------ profiles
class ProfileIn(BaseModel):
    kind: str = Field(..., pattern="^(vip|vendor)$")
    name: str = Field(..., min_length=2, max_length=120)
    emails: list[str] = []
    domains: list[str] = []
    notes: str = Field("", max_length=500)


@router.get("/profiles")
def list_profiles():
    return state.db.all("SELECT * FROM profiles ORDER BY kind, name")


@router.post("/profiles")
def add_profile(p: ProfileIn):
    pid = state.db.insert("profiles", {"kind": p.kind, "name": p.name.strip(), "emails_json": [e.strip().lower() for e in p.emails if e.strip()],
                                       "domains_json": [d.strip().lower() for d in p.domains if d.strip()], "notes": p.notes,
                                       "created_at": now(), "data_label": "user"})
    audit(state.db, "profile.created", "local-analyst", "profile", str(pid), "ok", f"{p.kind}: {p.name}")
    return state.db.one("SELECT * FROM profiles WHERE id=?", (pid,))


@router.delete("/profiles/{pid}")
def delete_profile(pid: int):
    state.db.execute("DELETE FROM profiles WHERE id=?", (pid,))
    audit(state.db, "profile.deleted", "local-analyst", "profile", str(pid), "ok")
    return {"deleted": pid}
