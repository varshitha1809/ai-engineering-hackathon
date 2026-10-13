"""Signature 4 — robustness lab: runs the REAL pipeline on the labelled suite and computes metrics.

Suites
  fixtures         synthetic labelled cases + validated variants (headers/HTML/attachments present)
  dataset_holdout  stratified sample of the ML test split (anonymised body text only; header/URL/attachment
                   layers cannot fire there, so it measures the content path)

baseline = trained text model alone (score >= tuned threshold)
hybrid   = full pipeline; "flagged" = LIKELY_PHISHING | SUSPICIOUS_REVIEW | AI_INJECTION_SUSPECTED
"""
from __future__ import annotations

import json
import threading
import time
import traceback
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from ..analysis import fusion
from ..analysis.context import Profile
from ..config import FUSION_VERSION, RULES_VERSION, REPO_ROOT
from ..db import Database
from ..email_processing.parser import looks_like_rfc822
from .variants import TRANSFORMS, make_variant

FLAGGED = {"LIKELY_PHISHING", "SUSPICIOUS_REVIEW", "AI_INJECTION_SUSPECTED"}
SUITE_PATH = REPO_ROOT / "data" / "fixtures" / "benchmark" / "benchmark_v1.json"
COMPONENTS = ["text_model", "intent", "identity", "url", "attachment", "evasion", "context", "ai_injection", "reputation"]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def binary_metrics(y: list[int], pred: list[int], scores: list[float] | None = None) -> dict:
    y_a, p_a = np.array(y), np.array(pred)
    tp = int(((p_a == 1) & (y_a == 1)).sum())
    fp = int(((p_a == 1) & (y_a == 0)).sum())
    tn = int(((p_a == 0) & (y_a == 0)).sum())
    fn = int(((p_a == 0) & (y_a == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    out = {"n": len(y), "positives": int(y_a.sum()), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
           "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
           "fpr": round(fp / (fp + tn), 4) if fp + tn else None}
    if scores is not None and 0 < y_a.sum() < len(y_a):
        from sklearn.metrics import average_precision_score
        out["pr_auc"] = round(float(average_precision_score(y_a, np.array(scores))), 4)
    return out


class BenchmarkRunner:
    def __init__(self, engine, db: Database):
        self.engine = engine
        self.db = db
        self._threads: dict[str, threading.Thread] = {}

    def load_suite(self) -> dict:
        return json.loads(Path(SUITE_PATH).read_text(encoding="utf-8"))

    def build_items(self, suite: dict, variants: bool, splits: list[str]) -> tuple[list[dict], list[dict]]:
        base = [c | {"base_id": c["id"], "transform": "original", "validation": "base case"} for c in suite["cases"]
                if c["split"] in splits]
        items, dropped = list(base), []
        if variants:
            for c in base:
                for t in TRANSFORMS:
                    v, note = make_variant(c, t)
                    if v:
                        items.append(v)
                    elif "validation failed" in note:
                        dropped.append({"base_id": c["id"], "transform": t, "reason": note})
        return items, dropped

    def start(self, suite_name: str = "fixtures", variants: bool = True, splits: list[str] | None = None,
              dataset_sample: int = 600) -> str:
        if self.engine.model.status != "loaded" and suite_name == "dataset_holdout":
            raise RuntimeError("model not loaded; dataset_holdout suite needs the trained model")
        rid = f"EVAL-{datetime.now(timezone.utc).strftime('%y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        params = {"suite": suite_name, "variants": variants, "splits": splits or ["dev", "holdout"],
                  "dataset_sample": dataset_sample}
        self.db.insert("evaluation_runs", {"id": rid, "suite": suite_name, "status": "queued", "progress": 0, "total": 0,
                                           "started_at": now(), "params_json": params, "model_version": self.engine.model.version,
                                           "rules_version": RULES_VERSION, "fusion_version": FUSION_VERSION})
        th = threading.Thread(target=self._run, args=(rid, params), daemon=True)
        self._threads[rid] = th
        th.start()
        return rid

    # ------------------------------------------------------------------ execution
    def _run(self, rid: str, params: dict) -> None:
        try:
            if params["suite"] == "dataset_holdout":
                items, dropped, profiles, org, limitations = self._dataset_items(params["dataset_sample"])
            else:
                suite = self.load_suite()
                items, dropped = self.build_items(suite, params["variants"], params["splits"])
                profiles = [Profile(i + 1, p["kind"], p["name"], p["emails"], p["domains"]) for i, p in enumerate(suite["profiles"])]
                org = suite["org_domains"]
                limitations = suite["limitations"]
            self.db.update("evaluation_runs", "id", rid, {"status": "running", "total": len(items)})
            rows = []
            for i, it in enumerate(items):
                raw = it["raw"].encode("utf-8")
                src = "eml" if looks_like_rfc822(it["raw"]) else "paste"
                t0 = time.perf_counter()
                try:
                    res = self.engine.analyze(raw, src, persist=False, correlate=False, profiles_override=profiles,
                                              org_domains_override=org)
                    err = None
                except Exception as exc:
                    res, err = None, f"{type(exc).__name__}: {exc}"
                lat = (time.perf_counter() - t0) * 1000
                b_score = res["model"]["score"] if res and res.get("model") else None
                thr = self.engine.model.threshold
                row = {"run_id": rid, "item_id": it["id"], "base_id": it.get("base_id", it["id"]), "category": it["category"],
                       "transform": it.get("transform", "original"), "label": it["label"],
                       "baseline_score": b_score, "baseline_pred": None if b_score is None else int(b_score >= thr),
                       "hybrid_score": res["risk_score"] if res else None, "hybrid_verdict": res["verdict"] if res else "ERROR",
                       "hybrid_pred": int(res["verdict"] in FLAGGED) if res else None,
                       "strengths_json": res["strengths"] if res else {}, "latency_ms": round(lat, 2),
                       "detail_json": {
                           "split": it.get("split"), "validation": it.get("validation"), "error": err,
                           "model_latency_ms": (res or {}).get("model", {}) and res["model"]["latency_ms"],
                           "decision_reasons": res["decision"]["decision_reasons"] if res else [],
                           "fusion_input": res["fusion_input"] if res else None,
                           "top_findings": [{k: f[k] for k in ("finding_id", "title", "component", "confidence", "status",
                                                               "observed_value", "source_location")}
                                            for f in sorted(res["findings"], key=lambda f: -f["confidence"])[:6]] if res else [],
                           "stage_status": res["stage_status"] if res else {},
                           "subject": res["parsed"]["subject"] if res else "", "notes": it.get("notes", "")}}
                self.db.insert("evaluation_items", row, replace=True)
                rows.append(row)
                if i % 5 == 0 or i == len(items) - 1:
                    self.db.update("evaluation_runs", "id", rid, {"progress": i + 1})
            metrics = self.compute_metrics(rows, self.engine.model.threshold)
            metrics["dropped_variants"] = dropped
            metrics["limitations"] = limitations
            metrics["data_label"] = ("synthetic benchmark data" if params["suite"] == "fixtures"
                                     else "held-out ML test split sample (MeAJOR/Nazario_5, anonymised)")
            self.db.update("evaluation_runs", "id", rid, {"status": "completed", "finished_at": now(), "metrics_json": metrics,
                                                          "progress": len(items)})
            out = REPO_ROOT / "data" / "reports" / f"benchmark_{rid}.json"
            out.write_text(json.dumps({"run_id": rid, "params": params, "model_version": self.engine.model.version,
                                       "rules_version": RULES_VERSION, "fusion_version": FUSION_VERSION, "metrics": metrics},
                                      indent=1, default=str))
        except Exception as exc:
            self.db.update("evaluation_runs", "id", rid, {"status": "failed", "finished_at": now(),
                                                          "error": f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-1500:]}"})

    def _dataset_items(self, n: int):
        import pandas as pd
        df = pd.read_parquet(REPO_ROOT / "data" / "processed" / "corpus.parquet", columns=["dataset", "label", "text", "split"])
        test = df[df.split == "test"]
        parts = []
        for (d, l), g in test.groupby(["dataset", "label"]):
            k = max(1, int(round(n * len(g) / len(test))))
            parts.append(g.sample(n=min(k, len(g)), random_state=7))
        sample = pd.concat(parts)
        items = [{"id": f"ds-{i}", "category": f"{r.dataset}_{'malicious' if r.label else 'benign'}", "label": int(r.label),
                  "split": "holdout", "raw": r.text, "has_headers": False, "transform": "original"}
                 for i, r in zip(sample.index, sample.itertuples())]
        lim = ["Body text only (dataset is anonymised and has no raw headers/HTML/attachments): identity, URL, attachment and "
               "hidden-content layers cannot fire, so hybrid ≈ text model + intent rules here.",
               "Text was already normalised by the training pipeline (lower-cased, URLs replaced by tokens)."]
        return items, [], [], ["phishdna-demo.local"], lim

    # ------------------------------------------------------------------ metrics
    def compute_metrics(self, rows: list[dict], thr: float) -> dict:
        lab = [r for r in rows if r["label"] is not None and r["hybrid_pred"] is not None]
        res: dict = {"threshold_text_model": thr, "flag_definition": sorted(FLAGGED)}

        def block(subset):
            y = [r["label"] for r in subset]
            with_b = [r for r in subset if r["baseline_pred"] is not None]
            return {"baseline": binary_metrics([r["label"] for r in with_b], [r["baseline_pred"] for r in with_b],
                                               [r["baseline_score"] for r in with_b]) if with_b else None,
                    "hybrid": binary_metrics(y, [r["hybrid_pred"] for r in subset], [r["hybrid_score"] / 100 for r in subset])}

        res["overall"] = block(lab)
        res["by_split"] = {s: block([r for r in lab if r["detail_json"]["split"] == s])
                           for s in ("dev", "holdout") if any(r["detail_json"]["split"] == s for r in lab)}
        res["originals_only"] = block([r for r in lab if r["transform"] == "original"])
        res["variants_only"] = block([r for r in lab if r["transform"] != "original"]) if any(r["transform"] != "original" for r in lab) else None
        # confusion matrix (hybrid & baseline, overall)
        res["confusion"] = {k: {kk: res["overall"][k][kk] for kk in ("tp", "fp", "tn", "fn")} for k in ("baseline", "hybrid") if res["overall"][k]}
        # per category / per transform
        per_cat = defaultdict(list)
        per_tr = defaultdict(list)
        for r in lab:
            per_cat[r["category"]].append(r)
            per_tr[r["transform"]].append(r)

        def rate(subset, key):
            vals = [r[key] for r in subset if r[key] is not None]
            return round(sum(vals) / len(vals), 4) if vals else None

        res["per_category"] = {c: {"n": len(v), "label": v[0]["label"], "baseline_flag_rate": rate(v, "baseline_pred"),
                                   "hybrid_flag_rate": rate(v, "hybrid_pred"),
                                   "metric": "recall" if v[0]["label"] == 1 else "false-positive rate"}
                               for c, v in sorted(per_cat.items())}
        res["per_transform"] = {}
        for t, v in sorted(per_tr.items()):
            mal = [r for r in v if r["label"] == 1]
            ben = [r for r in v if r["label"] == 0]
            res["per_transform"][t] = {"n": len(v), "malicious_n": len(mal), "benign_n": len(ben),
                                       "baseline_recall": rate(mal, "baseline_pred"), "hybrid_recall": rate(mal, "hybrid_pred"),
                                       "baseline_fpr": rate(ben, "baseline_pred"), "hybrid_fpr": rate(ben, "hybrid_pred")}
        # ablation: recompute the verdict policy on stored fusion inputs with one layer disabled
        abl = {}
        for layer in ["none"] + COMPONENTS:
            preds = []
            for r in lab:
                fi_d = r["detail_json"]["fusion_input"]
                if not fi_d:
                    preds.append(0)
                    continue
                fi = fusion.FusionInput(**fi_d)
                d = fusion.decide(fi, disabled=set() if layer == "none" else {layer})
                preds.append(int(d["verdict"] in FLAGGED))
            m = binary_metrics([r["label"] for r in lab], preds)
            abl["full hybrid" if layer == "none" else f"without {layer}"] = {k: m[k] for k in ("precision", "recall", "f1", "fpr", "fn", "fp")}
        res["ablation"] = abl
        # coverage matrix: share of items in each category where each layer produced evidence
        cov = {}
        for c, v in per_cat.items():
            cov[c] = {comp: round(sum(1 for r in v if (r["strengths_json"] or {}).get(comp, 0) > (0.0 if comp != "text_model" else thr)) / len(v), 3)
                      for comp in COMPONENTS}
        res["coverage_matrix"] = {"definition": "fraction of items where the layer produced evidence (text_model: score above threshold)",
                                  "rows": cov}
        # latency
        lat = [r["latency_ms"] for r in rows]
        mlat = [r["detail_json"].get("model_latency_ms") for r in rows if r["detail_json"].get("model_latency_ms")]
        res["latency_ms"] = {"hybrid_p50": round(float(np.percentile(lat, 50)), 2), "hybrid_p95": round(float(np.percentile(lat, 95)), 2),
                             "model_p50": round(float(np.percentile(mlat, 50)), 2) if mlat else None,
                             "model_p95": round(float(np.percentile(mlat, 95)), 2) if mlat else None, "n": len(lat)}
        # failures and baseline/hybrid disagreements
        def brief(r):
            return {"item_id": r["item_id"], "base_id": r["base_id"], "category": r["category"], "transform": r["transform"],
                    "label": r["label"], "baseline_score": r["baseline_score"], "hybrid_verdict": r["hybrid_verdict"],
                    "hybrid_score": r["hybrid_score"], "subject": r["detail_json"].get("subject", ""),
                    "decision_reasons": r["detail_json"]["decision_reasons"], "top_findings": r["detail_json"]["top_findings"][:4],
                    "explanation": self._failure_explanation(r, thr)}
        res["failures"] = {"hybrid_false_negatives": [brief(r) for r in lab if r["label"] == 1 and r["hybrid_pred"] == 0],
                           "hybrid_false_positives": [brief(r) for r in lab if r["label"] == 0 and r["hybrid_pred"] == 1],
                           "baseline_false_negatives": len([r for r in lab if r["label"] == 1 and r["baseline_pred"] == 0]),
                           "baseline_false_positives": len([r for r in lab if r["label"] == 0 and r["baseline_pred"] == 1])}
        res["disagreements"] = {
            "baseline_missed_hybrid_caught": [brief(r) for r in lab if r["label"] == 1 and r["baseline_pred"] == 0 and r["hybrid_pred"] == 1][:40],
            "hybrid_missed_baseline_caught": [brief(r) for r in lab if r["label"] == 1 and r["baseline_pred"] == 1 and r["hybrid_pred"] == 0][:40],
            "baseline_false_alarm_hybrid_cleared": [brief(r) for r in lab if r["label"] == 0 and r["baseline_pred"] == 1 and r["hybrid_pred"] == 0][:40]}
        amb = [r for r in rows if r["label"] is None]
        res["unlabelled_ambiguous"] = {"n": len(amb), "verdicts": dict(Counter(r["hybrid_verdict"] for r in amb)),
                                       "items": [{"item_id": r["item_id"], "verdict": r["hybrid_verdict"], "risk": r["hybrid_score"]} for r in amb]}
        res["errors"] = [{"item_id": r["item_id"], "error": r["detail_json"]["error"]} for r in rows if r["detail_json"].get("error")]
        res["counts"] = {"items": len(rows), "labelled": len(lab), "base_cases": len({r["base_id"] for r in rows}),
                         "variants": sum(1 for r in rows if r["transform"] != "original")}
        return res

    @staticmethod
    def _failure_explanation(r: dict, thr: float) -> str:
        s = r["strengths_json"] or {}
        fired = [f"{k}={v:.2f}" for k, v in s.items() if v > 0]
        b = r["baseline_score"]
        if r["label"] == 1:
            parts = [f"Missed: hybrid risk {r['hybrid_score']} stayed below the review threshold (35)."]
            if b is not None:
                parts.append(f"Text model {b:.2f} vs threshold {thr:.2f}.")
            parts.append(f"Layers with evidence: {', '.join(fired) or 'none'}.")
            if not s.get("intent"):
                parts.append("No requested action or tactic was extracted by the intent rules.")
            if r["transform"] != "original":
                parts.append(f"Variant '{r['transform']}' may have defeated the lexical rules.")
            return " ".join(parts)
        return (f"False alarm: verdict {r['hybrid_verdict']} because {'; '.join(r['detail_json']['decision_reasons'])}. "
                f"Layers with evidence: {', '.join(fired) or 'none'}.")
