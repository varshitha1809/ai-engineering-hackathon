"""Live inference with the saved scikit-learn pipeline (Model A).

The artifact's sha256 is verified against model_metadata.json before loading. If the model is
missing or fails, the stage is reported as failed — the fusion layer then cannot return a
"no strong indicators" verdict on model evidence alone.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

import numpy as np

from ..ml.text_prep import prep_live_text


class TextModel:
    def __init__(self, model_dir: Path):
        self.model_dir = model_dir
        self.pipe = None
        self.meta: dict[str, Any] = {}
        self.status = "not_loaded"
        self.error = ""
        self.loaded_at: float | None = None
        self._names: np.ndarray | None = None
        self._coef: np.ndarray | None = None
        self._lock = threading.Lock()

    @property
    def version(self) -> str:
        return self.meta.get("model_version", "unavailable")

    @property
    def threshold(self) -> float:
        return float(self.meta.get("decision_threshold", 0.5))

    def load(self) -> None:
        with self._lock:
            art = self.model_dir / "phishdna_text_model.joblib"
            meta_p = self.model_dir / "model_metadata.json"
            if not art.exists() or not meta_p.exists():
                self.status, self.error = "missing", f"artifact not found in {self.model_dir} - run scripts/train_model.py"
                return
            try:
                meta = json.loads(meta_p.read_text())
                sha = hashlib.sha256(art.read_bytes()).hexdigest()
                if sha != meta.get("artifact_sha256"):
                    self.status, self.error = "failed", "artifact sha256 does not match model_metadata.json"
                    return
                import joblib
                self.pipe = joblib.load(art)
                self.meta = meta
                self._prepare_explainer()
                self.status, self.error, self.loaded_at = "loaded", "", time.time()
            except Exception as exc:
                self.pipe = None
                self.status, self.error = "failed", f"{type(exc).__name__}: {exc}"

    def _prepare_explainer(self) -> None:
        feats = self.pipe.named_steps["features"]
        clf = self.pipe.named_steps["clf"]
        base = clf
        # unwrap CalibratedClassifierCV(FrozenEstimator(LinearSVC)) when an SVM was selected
        if hasattr(clf, "calibrated_classifiers_"):
            base = clf.calibrated_classifiers_[0].estimator
            base = getattr(base, "estimator", base)
        self._coef = np.asarray(base.coef_).ravel()
        self._names = feats.get_feature_names_out()

    def predict(self, subject: str, body: str, top_k: int = 8) -> dict:
        if self.status != "loaded" or self.pipe is None:
            raise RuntimeError(self.error or "model not loaded")
        text = prep_live_text(subject, body)
        t0 = time.perf_counter()
        X = self.pipe.named_steps["features"].transform([text])
        proba = float(self.pipe.named_steps["clf"].predict_proba(X)[0, 1])
        ms = (time.perf_counter() - t0) * 1000
        contrib = []
        if self._coef is not None:
            row = X.tocsr()
            vals = row.data * self._coef[row.indices]
            order = np.argsort(-np.abs(vals))[: top_k * 3]
            seen = set()
            for i in order:
                name = str(self._names[row.indices[i]])
                kind, term = name.split("__", 1)
                key = term.strip()
                if not key or key in seen:
                    continue
                seen.add(key)
                contrib.append({"feature": term, "type": "word n-gram" if kind == "word" else "character n-gram",
                                "contribution": round(float(vals[i]), 4),
                                "direction": "towards malicious" if vals[i] > 0 else "towards benign"})
                if len(contrib) >= top_k:
                    break
        return {"score": round(proba, 4), "threshold": self.threshold, "predicted_label": int(proba >= self.threshold),
                "margin": round(abs(proba - self.threshold), 4), "latency_ms": round(ms, 2), "input_tokens": len(text.split()),
                "top_contributions": contrib, "model_version": self.version,
                "explanation_method": "linear model: TF-IDF value × coefficient for features present in this email"}

    def predict_texts(self, texts: list[str]) -> np.ndarray:
        if self.status != "loaded" or self.pipe is None:
            raise RuntimeError(self.error or "model not loaded")
        return self.pipe.predict_proba(texts)[:, 1]

    def info(self) -> dict:
        keep = ("model_version", "run_id", "created_at", "classifier", "C", "training_pool", "train_rows", "n_features",
                "features", "decision_threshold", "threshold_selection", "calibration", "label_mapping", "prep_version",
                "artifact_sha256", "artifact_bytes", "sklearn_version", "selection_rule")
        return {"status": self.status, "error": self.error, **{k: self.meta.get(k) for k in keep}}
