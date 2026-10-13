"""Robustness lab endpoints + decision replay (policy what-if and shadow re-analysis)."""
from __future__ import annotations

import zlib

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ..analysis import fusion
from ..services.audit import audit
from ..state import state

router = APIRouter(prefix="/api/v1", tags=["evaluation"])


class RunIn(BaseModel):
    suite: str = Field("fixtures", pattern="^(fixtures|dataset_holdout)$")
    variants: bool = True
    splits: list[str] = ["dev", "holdout"]
    dataset_sample: int = Field(600, ge=50, le=5000)


@router.post("/evaluations/run")
def run(body: RunIn):
    running = state.db.scalar("SELECT COUNT(*) FROM evaluation_runs WHERE status IN ('queued','running')")
    if running:
        raise HTTPException(409, "a benchmark run is already in progress")
    try:
        rid = state.runner.start(body.suite, body.variants, body.splits, body.dataset_sample)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    audit(state.db, "evaluation.started", "local-analyst", "evaluation", rid, "ok", f"suite={body.suite} variants={body.variants}")
    return {"id": rid, "status": "queued"}


@router.get("/evaluations")
def list_runs(limit: int = Query(30, le=200)):
    rows = state.db.all("SELECT id, suite, status, progress, total, started_at, finished_at, params_json, model_version, "
                        "rules_version, fusion_version, error, metrics_json FROM evaluation_runs ORDER BY started_at DESC LIMIT ?", (limit,))
    for r in rows:
        m = r.pop("metrics_json") or {}
        r["summary"] = {"overall": m.get("overall"), "counts": m.get("counts")} if m else None
    return rows


@router.get("/evaluations/{rid}")
def get_run(rid: str):
    r = state.db.one("SELECT * FROM evaluation_runs WHERE id=?", (rid,))
    if not r:
        raise HTTPException(404, "evaluation run not found")
    return r


@router.get("/evaluations/{rid}/items")
def run_items(rid: str, only: str = Query("all", pattern="^(all|failures|disagreements)$"), limit: int = Query(500, le=5000)):
    rows = state.db.all("SELECT * FROM evaluation_items WHERE run_id=? ORDER BY item_id LIMIT ?", (rid, limit))
    if only == "failures":
        rows = [r for r in rows if r["label"] is not None and r["hybrid_pred"] is not None and r["hybrid_pred"] != r["label"]]
    elif only == "disagreements":
        rows = [r for r in rows if r["baseline_pred"] is not None and r["baseline_pred"] != r["hybrid_pred"]]
    return rows


@router.get("/evaluations/{rid}/items/{item_id}")
def run_item(rid: str, item_id: str):
    r = state.db.one("SELECT * FROM evaluation_items WHERE run_id=? AND item_id=?", (rid, item_id))
    if not r:
        raise HTTPException(404, "item not found")
    suite = state.runner.load_suite()
    base = next((c for c in suite["cases"] if c["id"] == r["base_id"]), None)
    r["base_case_notes"] = base["notes"] if base else ""
    return r


class ReplayIn(BaseModel):
    mode: str = Field("policy", pattern="^(policy|reanalyze)$")
    likely_threshold: float | None = Field(None, ge=0, le=100)
    review_threshold: float | None = Field(None, ge=0, le=100)
    strong_group_strength: float | None = Field(None, ge=0, le=1)
    strong_text_score: float | None = Field(None, ge=0, le=1)
    disabled_layers: list[str] = []
    limit: int = Field(500, ge=1, le=5000)


@router.post("/replay")
def replay(body: ReplayIn):
    """What-if: re-decide retained analyses under a different policy (stored inputs) or re-run the current
    model/rules on retained raw content in shadow mode (nothing is persisted)."""
    policy = {k: v for k, v in body.model_dump().items()
              if k in fusion.DEFAULT_POLICY and v is not None}
    rows = state.db.all("SELECT id, subject, verdict, risk_score, fusion_input_json, model_version, rules_version FROM analyses "
                        "ORDER BY created_at DESC LIMIT ?", (body.limit,))
    changes, unchanged, skipped = [], 0, 0
    for r in rows:
        if body.mode == "policy":
            fi_d = r["fusion_input_json"]
            if not isinstance(fi_d, dict):
                skipped += 1
                continue
            d = fusion.decide(fusion.FusionInput(**fi_d), policy, set(body.disabled_layers))
            new_v, new_s, ver = d["verdict"], d["risk_score"], "stored inputs"
        else:
            raw = state.db.scalar("SELECT raw FROM raw_inputs WHERE analysis_id=?", (r["id"],))
            if raw is None:
                skipped += 1
                continue
            res = state.engine.analyze(zlib.decompress(raw), "eml", persist=False, correlate=False)
            new_v, new_s, ver = res["verdict"], res["risk_score"], f"{res['versions']['model']} / {res['versions']['rules']}"
        if new_v != r["verdict"]:
            changes.append({"id": r["id"], "subject": r["subject"], "before": {"verdict": r["verdict"], "risk_score": r["risk_score"],
                                                                             "versions": f"{r['model_version']} / {r['rules_version']}"},
                            "after": {"verdict": new_v, "risk_score": new_s, "versions": ver}})
        else:
            unchanged += 1
    audit(state.db, "replay.run", "local-analyst", "replay", body.mode, "ok",
          f"policy={policy} disabled={body.disabled_layers} changed={len(changes)}")
    return {"mode": body.mode, "policy": {**fusion.DEFAULT_POLICY, **policy}, "disabled_layers": body.disabled_layers,
            "evaluated": len(rows) - skipped, "skipped_no_data": skipped, "changed": changes, "unchanged": unchanged,
            "note": "Shadow comparison only - stored verdicts were not modified."}
