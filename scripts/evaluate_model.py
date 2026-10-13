"""Final held-out evaluation of the saved model artifact.

Loads models/phishdna_text_model.joblib exactly as the backend does, scores the untouched TEST
splits (MeAJOR, Nazario_5) and the external SpamAssassin corpus, and writes
data/reports/evaluation_<run_id>.json plus models/evaluation_latest.json.

Metrics: precision, recall, F1, FPR, confusion matrix, per-class precision/recall/support,
PR-AUC, ROC-AUC, Brier + 10-bin ECE (reliability), per-source breakdown, single-email latency
p50/p95 and a sample of misclassified test rows for failure analysis.

Usage:  python scripts/evaluate_model.py
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_recall_fscore_support,
                             precision_score, recall_score, roc_auc_score)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PROC = ROOT / "data" / "processed"
MODELS = ROOT / "models"
REPORTS = ROOT / "data" / "reports"


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def ece(y, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    out, e = [], 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & ((p < hi) if hi < 1 else (p <= hi))
        if m.any():
            e += m.mean() * abs(p[m].mean() - y[m].mean())
            out.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": int(m.sum()), "mean_score": round(float(p[m].mean()), 4),
                        "observed_positive_rate": round(float(y[m].mean()), 4)})
    return round(float(e), 4), out


def full_metrics(y: np.ndarray, s: np.ndarray, thr: float) -> dict:
    p = (s >= thr).astype(int)
    labels = [0, 1]
    cm = confusion_matrix(y, p, labels=labels)
    tn, fp, fn, tp = (int(x) for x in cm.ravel())
    pr, rc, f1, sup = precision_recall_fscore_support(y, p, labels=labels, zero_division=0)
    both = 0 < y.sum() < len(y)
    e, rel = ece(y, s) if both else (None, [])
    return {
        "n": int(len(y)), "threshold": thr,
        "precision": round(float(precision_score(y, p, zero_division=0)), 4),
        "recall": round(float(recall_score(y, p, zero_division=0)), 4),
        "f1": round(float(f1_score(y, p, zero_division=0)), 4),
        "fpr": round(fp / max(fp + tn, 1), 4),
        "accuracy": round((tp + tn) / max(len(y), 1), 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "per_class": {("benign" if c == 0 else "malicious"): {"precision": round(float(pr[i]), 4), "recall": round(float(rc[i]), 4),
                                                               "f1": round(float(f1[i]), 4), "support": int(sup[i])}
                      for i, c in enumerate(labels)},
        "pr_auc": round(float(average_precision_score(y, s)), 4) if both else None,
        "roc_auc": round(float(roc_auc_score(y, s)), 4) if both else None,
        "brier": round(float(np.mean((s - y) ** 2)), 4),
        "ece_10bin": e, "reliability": rel,
    }


def main() -> int:
    art = MODELS / "phishdna_text_model.joblib"
    meta_path = MODELS / "model_metadata.json"
    if not art.exists() or not meta_path.exists():
        log("BLOCKER: model artifact missing - run scripts/train_model.py")
        return 2
    meta = json.loads(meta_path.read_text())
    sha = hashlib.sha256(art.read_bytes()).hexdigest()
    if sha != meta["artifact_sha256"]:
        log("BLOCKER: artifact sha256 does not match metadata")
        return 3
    pipe = joblib.load(art)
    thr = float(meta["decision_threshold"])
    df = pd.read_parquet(PROC / "corpus.parquet")
    run_id = f"eval-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"
    result = {"run_id": run_id, "created_at": datetime.now(timezone.utc).isoformat(), "model_version": meta["model_version"],
              "training_run_id": meta["run_id"], "artifact_sha256": sha, "decision_threshold": thr,
              "evaluation_sets": {}, "notes": [
                  "Test splits were not used for model selection, threshold tuning or calibration.",
                  "MeAJOR label 1 in this file derives from TREC spam labels; MeAJOR metrics measure malicious/unsolicited "
                  "detection broadly, Nazario_5 metrics measure phishing vs legitimate.",
                  "SpamAssassin is an unseen external corpus with spam/ham labels; its 'recall' is spam recall, not phishing recall.",
              ]}
    sets = {
        "meajor_test": df[(df.split == "test") & (df.dataset == "meajor")],
        "nazario_5_test": df[(df.split == "test") & (df.dataset == "nazario_5")],
        "combined_test": df[df.split == "test"],
        "spamassassin_external": df[df.split == "external_test"],
    }
    failures = []
    for name, part in sets.items():
        if part.empty:
            result["evaluation_sets"][name] = {"status": "unavailable"}
            continue
        t0 = time.time()
        s = pipe.predict_proba(part.text.tolist())[:, 1]
        m = full_metrics(part.label.values, s, thr)
        m["batch_seconds"] = round(time.time() - t0, 2)
        if name == "meajor_test":
            m["per_source"] = {}
            for src, g in part.assign(score=s).groupby("source"):
                m["per_source"][src] = {k: v for k, v in full_metrics(g.label.values, g.score.values, thr).items()
                                        if k not in ("reliability",)}
        result["evaluation_sets"][name] = m
        log(f"{name}: n={m['n']} P={m['precision']} R={m['recall']} F1={m['f1']} FPR={m['fpr']} PR-AUC={m['pr_auc']}")
        if name in ("meajor_test", "nazario_5_test"):
            wrong = part.assign(score=s)[(s >= thr).astype(int) != part.label.values]
            for _, r in wrong.sort_values("score").head(40).iterrows():
                failures.append({"set": name, "label": int(r.label), "score": round(float(r.score), 4),
                                 "kind": "false_negative" if r.label == 1 else "false_positive",
                                 "excerpt": r.text[:300]})

    # single-email latency (end-to-end pipeline.predict_proba on one prepped text)
    sample = sets["combined_test"].sample(n=min(300, len(sets["combined_test"])), random_state=0).text.tolist()
    lat = []
    for t in sample:
        t0 = time.perf_counter()
        pipe.predict_proba([t])
        lat.append((time.perf_counter() - t0) * 1000)
    result["latency_ms_single_email"] = {"n": len(lat), "p50": round(float(np.percentile(lat, 50)), 2),
                                         "p95": round(float(np.percentile(lat, 95)), 2)}
    result["failure_samples"] = failures
    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / f"evaluation_{run_id}.json"
    out.write_text(json.dumps(result, indent=2))
    (MODELS / "evaluation_latest.json").write_text(json.dumps(result, indent=2))
    log(f"latency p50={result['latency_ms_single_email']['p50']}ms p95={result['latency_ms_single_email']['p95']}ms")
    log(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
