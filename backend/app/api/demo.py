"""Import the labelled local demo sample set (profiles, local IOC list, sample messages)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException

from ..config import REPO_ROOT
from ..services.audit import audit
from ..state import state

router = APIRouter(prefix="/api/v1", tags=["demo"])
DEMO = REPO_ROOT / "data" / "fixtures" / "demo"


@router.get("/demo/samples")
def samples():
    man = DEMO / "demo_manifest.json"
    if not man.exists():
        raise HTTPException(404, "demo fixtures missing - run python scripts/build_demo_fixtures.py")
    m = json.loads(man.read_text(encoding="utf-8"))
    out = []
    for f in m["files"]:
        raw = (DEMO / f).read_text(encoding="utf-8")
        subj = next((l[9:] for l in raw.splitlines() if l.startswith("Subject: ")), f)
        out.append({"file": f, "subject": subj, "raw": raw})
    return {"data_label": m["data_label"], "samples": out, "expected_relationships": m["expected_relationships"]}


@router.post("/demo/seed")
def seed():
    man = DEMO / "demo_manifest.json"
    if not man.exists():
        raise HTTPException(404, "demo fixtures missing - run python scripts/build_demo_fixtures.py")
    m = json.loads(man.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc).isoformat()
    added_profiles = 0
    for p in m["profiles"]:
        if not state.db.one("SELECT id FROM profiles WHERE name=? AND kind=?", (p["name"], p["kind"])):
            state.db.insert("profiles", {"kind": p["kind"], "name": p["name"], "emails_json": p["emails"], "domains_json": p["domains"],
                                         "notes": p["notes"], "created_at": now, "data_label": "local demo"})
            added_profiles += 1
    for i in m["local_iocs"]:
        state.db.execute("INSERT INTO indicators (type, value, display_value, first_seen_local, last_seen_local, sightings, reputation, "
                         "reputation_source, reputation_checked_at, review_status, expires_at, notes) VALUES (?,?,?,?,?,0,?,?,?,?,?,?) "
                         "ON CONFLICT(type, value) DO UPDATE SET reputation=excluded.reputation, reputation_source=excluded.reputation_source, "
                         "review_status='approved'",
                         (i["type"], i["value"].lower(), i["value"], now, now, i["reputation"], i["source"], now, "approved",
                          (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(), i["notes"]))
    results = []
    for f in m["files"]:
        raw = (DEMO / f).read_bytes()
        r = state.engine.analyze(raw, "eml", data_label="local sample data", batch_id="DEMO")
        results.append({"file": f, "id": r["id"], "verdict": r["verdict"], "risk_score": r["risk_score"]})
    audit(state.db, "demo.seeded", "local-analyst", "batch", "DEMO", "ok", f"{len(results)} sample messages, {added_profiles} profiles")
    return {"data_label": m["data_label"], "profiles_added": added_profiles, "iocs": len(m["local_iocs"]), "results": results,
            "campaigns": state.db.all("SELECT id, label, member_count, severity FROM campaigns")}
