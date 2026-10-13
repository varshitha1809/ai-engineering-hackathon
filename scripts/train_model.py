"""Train the PHISHDNA text classifier (Model A) and save the complete fitted pipeline.

  * Features: word 1-2gram TF-IDF + character 3-5gram (char_wb) TF-IDF, fitted on TRAIN only.
  * Candidates: Logistic Regression (C grid) and linear SVM (C grid), each on two training pools
    (MeAJOR only / MeAJOR + Nazario_5). Selection = mean F1 over the MeAJOR and Nazario_5
    VALIDATION splits. The test splits are never touched here.
  * Decision threshold is tuned on validation. If an SVM is selected its scores are calibrated
    with a sigmoid fitted on validation; LR probabilities are reported with a reliability check.
  * Artifacts: models/phishdna_text_model.joblib + models/model_metadata.json (+ sha256).

Usage:  python scripts/train_model.py [--quick]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, precision_recall_curve, precision_score, recall_score
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.ml.text_prep import PREP_VERSION, truncate_for_char  # noqa: E402

PROC = ROOT / "data" / "processed"
MODELS = ROOT / "models"
REPORTS = ROOT / "data" / "reports"
SEED = 42


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def make_features(quick: bool) -> FeatureUnion:
    mf = 50_000 if quick else 300_000
    return FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_df=0.95, max_features=mf, sublinear_tf=True,
                                 token_pattern=r"(?u)\b\w[\w'-]*\b", dtype=np.float32)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=5, max_features=mf, sublinear_tf=True,
                                 preprocessor=truncate_for_char, dtype=np.float32)),
    ])


def scores_of(clf, X) -> np.ndarray:
    if hasattr(clf, "predict_proba"):
        return clf.predict_proba(X)[:, 1]
    return clf.decision_function(X)


def metrics(y: np.ndarray, s: np.ndarray, thr: float) -> dict:
    p = (s >= thr).astype(int)
    tn = int(((p == 0) & (y == 0)).sum())
    fp = int(((p == 1) & (y == 0)).sum())
    return {"n": int(len(y)), "positives": int(y.sum()), "precision": round(float(precision_score(y, p, zero_division=0)), 4),
            "recall": round(float(recall_score(y, p, zero_division=0)), 4), "f1": round(float(f1_score(y, p, zero_division=0)), 4),
            "fpr": round(fp / max(fp + tn, 1), 4),
            "pr_auc": round(float(average_precision_score(y, s)), 4) if 0 < y.sum() < len(y) else None}


def best_threshold(y: np.ndarray, s: np.ndarray) -> float:
    prec, rec, thr = precision_recall_curve(y, s)
    f1 = 2 * prec * rec / np.clip(prec + rec, 1e-9, None)
    i = int(np.nanargmax(f1[:-1]))
    return float(thr[i])


def ece(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    e = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & (p < hi) if hi < 1 else (p >= lo) & (p <= hi)
        if m.any():
            e += m.mean() * abs(p[m].mean() - y[m].mean())
    return round(float(e), 4)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="smaller vocab + fewer candidates (smoke test)")
    args = ap.parse_args()
    corpus_path = PROC / "corpus.parquet"
    if not corpus_path.exists():
        log("BLOCKER: data/processed/corpus.parquet missing - run scripts/preprocess_dataset.py")
        return 2
    df = pd.read_parquet(corpus_path)
    run_id = f"train-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"
    log(f"run {run_id}: corpus {len(df)} rows")
    tr = df[df.split == "train"]
    va = df[df.split == "val"]
    va_sets = {"meajor": va[va.dataset == "meajor"], "nazario_5": va[va.dataset == "nazario_5"]}
    pools = {"meajor_only": tr[tr.dataset == "meajor"], "meajor+nazario_5": tr}
    lr_grid = [1.0, 4.0] if not args.quick else [4.0]
    svm_grid = [0.1, 0.5] if not args.quick else [0.5]

    candidates = []
    fitted = {}
    for pool_name, pool in pools.items():
        log(f"pool {pool_name}: fitting TF-IDF on {len(pool)} training rows")
        t0 = time.time()
        feats = make_features(args.quick)
        Xtr = feats.fit_transform(pool.text.tolist())
        feat_time = time.time() - t0
        ytr = pool.label.values
        Xva = {k: feats.transform(v.text.tolist()) for k, v in va_sets.items()}
        log(f"  features {Xtr.shape[1]} in {feat_time:.0f}s")
        for kind, grid in (("logreg", lr_grid), ("linear_svm", svm_grid)):
            for C in grid:
                t1 = time.time()
                clf = (LogisticRegression(C=C, solver="liblinear", max_iter=2000, random_state=SEED) if kind == "logreg"
                       else LinearSVC(C=C, max_iter=5000, random_state=SEED))
                clf.fit(Xtr, ytr)
                fit_s = time.time() - t1
                # threshold tuned on the concatenated validation set
                yv = np.concatenate([v.label.values for v in va_sets.values()])
                sv = np.concatenate([scores_of(clf, Xva[k]) for k in va_sets])
                thr = best_threshold(yv, sv)
                per = {k: metrics(va_sets[k].label.values, scores_of(clf, Xva[k]), thr) for k in va_sets}
                sel = round((per["meajor"]["f1"] + per["nazario_5"]["f1"]) / 2, 4)
                cid = f"{pool_name}|{kind}|C={C}"
                candidates.append({"id": cid, "pool": pool_name, "classifier": kind, "C": C, "train_rows": int(len(pool)),
                                   "n_features": int(Xtr.shape[1]), "fit_seconds": round(fit_s, 1),
                                   "feature_seconds": round(feat_time, 1), "val_threshold": round(thr, 6),
                                   "val": per, "selection_score_mean_f1": sel})
                fitted[cid] = (feats, clf)
                log(f"  {cid}: val meajor F1={per['meajor']['f1']} nazario_5 F1={per['nazario_5']['f1']} "
                    f"(sel={sel}, fit {fit_s:.0f}s)")

    best = max(candidates, key=lambda c: (c["selection_score_mean_f1"], -c["fit_seconds"]))
    log(f"selected {best['id']}")
    feats, clf = fitted[best["id"]]
    yv = np.concatenate([v.label.values for v in va_sets.values()])
    Xv = feats.transform(pd.concat(va_sets.values()).text.tolist())
    calibration = {}
    if best["classifier"] == "linear_svm":
        from sklearn.frozen import FrozenEstimator
        cal = CalibratedClassifierCV(FrozenEstimator(clf), method="sigmoid")
        cal.fit(Xv, yv)
        final_clf = cal
        calibration["method"] = "sigmoid (Platt) fitted on validation split"
    else:
        final_clf = clf
        calibration["method"] = "none (raw logistic-regression probabilities)"
    pv = final_clf.predict_proba(Xv)[:, 1]
    thr = best_threshold(yv, pv)
    calibration["val_brier"] = round(float(np.mean((pv - yv) ** 2)), 4)
    calibration["val_ece_10bin"] = ece(yv, pv)
    calibration["note"] = ("Reliability measured on validation; the backend still presents the fused output as a "
                           "0-100 policy risk score, not a probability.")

    pipe = Pipeline([("features", feats), ("clf", final_clf)])
    MODELS.mkdir(exist_ok=True)
    art = MODELS / "phishdna_text_model.joblib"
    joblib.dump(pipe, art, compress=3)
    sha = hashlib.sha256(art.read_bytes()).hexdigest()
    split_manifest = json.loads((PROC / "split_manifest.json").read_text())
    meta = {
        "model_version": f"textclf-{best['classifier']}-{sha[:10]}",
        "run_id": run_id, "created_at": datetime.now(timezone.utc).isoformat(),
        "artifact": art.name, "artifact_sha256": sha, "artifact_bytes": art.stat().st_size,
        "classifier": best["classifier"], "C": best["C"], "training_pool": best["pool"], "train_rows": best["train_rows"],
        "n_features": best["n_features"], "features": "word 1-2gram TF-IDF (sublinear) + char_wb 3-5gram TF-IDF (first 4000 chars)",
        "label_mapping": {"0": "benign", "1": "malicious (MeAJOR label 1 / Nazario phishing)"},
        "decision_threshold": round(thr, 6), "threshold_selection": "max F1 on validation (MeAJOR val + Nazario_5 val)",
        "calibration": calibration, "prep_version": PREP_VERSION, "corpus_sha256": split_manifest["corpus_sha256"],
        "seed": SEED, "sklearn_version": sklearn.__version__, "python": platform.python_version(),
        "candidates": candidates, "selection_rule": "highest mean validation F1 across MeAJOR and Nazario_5; tie -> faster fit",
        "quick_mode": bool(args.quick),
    }
    (MODELS / "model_metadata.json").write_text(json.dumps(meta, indent=2))
    REPORTS.mkdir(parents=True, exist_ok=True)
    runs = REPORTS / "training_runs.jsonl"
    with open(runs, "a", encoding="utf-8") as f:
        f.write(json.dumps({k: meta[k] for k in ("run_id", "created_at", "model_version", "classifier", "C", "training_pool",
                                                    "decision_threshold", "artifact_sha256", "quick_mode")} | {"candidates": candidates}) + "\n")
    log(f"saved {art} ({art.stat().st_size / 1e6:.1f} MB) sha256={sha[:12]} threshold={thr:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
