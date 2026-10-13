import hashlib
import json

import numpy as np
import pytest

from backend.app.analysis import fusion
from backend.app.analysis.model import TextModel
from backend.app.config import settings
from backend.app.evaluation.benchmark import binary_metrics
from backend.app.ml.text_prep import prep_dataset_text, prep_live_text

from .conftest import eml


# ---------------------------------------------------------------- ML artifact
def test_artifact_exists_hash_matches_and_loads(model):
    meta = json.loads((settings.model_dir / "model_metadata.json").read_text())
    art = settings.model_dir / meta["artifact"]
    assert hashlib.sha256(art.read_bytes()).hexdigest() == meta["artifact_sha256"]
    assert model.status == "loaded", model.error
    assert meta["label_mapping"]["1"].startswith("malicious") and meta["label_mapping"]["0"] == "benign"


def test_predictions_are_consistent_and_label_mapping_is_correct(model):
    phish = "Your account has been suspended. Verify your password immediately at http://secure-login.test to avoid closure."
    benign = "Hi team, the planning meeting moved to Thursday 3pm in room 4B. Agenda is in the shared drive. Thanks, Priya"
    a1, a2 = model.predict("Account suspended", phish)["score"], model.predict("Account suspended", phish)["score"]
    assert a1 == a2
    assert model.predict("Account suspended", phish)["score"] > model.predict("Meeting moved", benign)["score"]
    out = model.predict("Account suspended", phish)
    assert out["top_contributions"] and {"feature", "contribution", "direction"} <= set(out["top_contributions"][0])


def test_train_and_serve_preprocessing_agree():
    assert prep_dataset_text("Hi", "visit <|URL|> now") == prep_live_text("Hi", "visit https://x.test/a now")
    assert "emailtoken" in prep_live_text("", "write to a.b@x.test")
    assert "[name]" not in prep_dataset_text("", "Dear [NAME], thanks")


def test_missing_model_never_yields_safe_verdict(tmp_path, engine):
    engine.model = TextModel(tmp_path / "nowhere")
    engine.model.load()
    assert engine.model.status == "missing"
    r = engine.analyze(b"Hello, see you at lunch tomorrow, the usual place near the office.", "paste", persist=False, correlate=False)
    assert r["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert r["stage_status"]["text_model"]["status"] == "failed"
    assert any(f["category"] == "model.unavailable" for f in r["findings"])


def test_tampered_artifact_is_rejected(tmp_path):
    (tmp_path / "phishdna_text_model.joblib").write_bytes(b"not a model")
    (tmp_path / "model_metadata.json").write_text(json.dumps({"artifact_sha256": "0" * 64}))
    m = TextModel(tmp_path)
    m.load()
    assert m.status == "failed" and "sha256" in m.error
    with pytest.raises(RuntimeError):
        m.predict("a", "b")


def test_metrics_reproducible_and_correct():
    y = [1, 1, 0, 0, 1, 0]
    p = [1, 0, 0, 1, 1, 0]
    m = binary_metrics(y, p, [0.9, 0.4, 0.1, 0.7, 0.8, 0.2])
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (2, 1, 2, 1)
    assert m["precision"] == round(2 / 3, 4) and m["recall"] == round(2 / 3, 4) and m["fpr"] == round(1 / 3, 4)
    assert binary_metrics(y, p, [0.9, 0.4, 0.1, 0.7, 0.8, 0.2]) == m


def test_saved_evaluation_report_is_from_held_out_predictions():
    ev = json.loads((settings.model_dir / "evaluation_latest.json").read_text())
    meta = json.loads((settings.model_dir / "model_metadata.json").read_text())
    assert ev["artifact_sha256"] == meta["artifact_sha256"]
    cm = ev["evaluation_sets"]["meajor_test"]["confusion_matrix"]
    n = ev["evaluation_sets"]["meajor_test"]["n"]
    assert cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"] == n


# ---------------------------------------------------------------- fusion & provenance
def _fi(**kw):
    base = dict(strengths={g: 0.0 for g in fusion.GROUPS}, model_status="loaded", model_score=0.1, model_threshold=0.5,
                high_impact_actions=[], identity_verified=False, word_count=50, headers_present=True, parse_ok=True)
    base.update(kw)
    return fusion.FusionInput(**base)


def test_correlated_evidence_does_not_stack_linearly():
    many = fusion.group_strengths([], None)
    assert many["intent"] == 0
    from backend.app.analysis.evidence import Collector
    c = Collector()
    for _ in range(10):
        c.add(category="tactic.urgency", component="intent", severity="low", title="t", observed_value="", source_location="body",
              method="rule", version="v", confidence=0.35, status="observed", explanation="")
    s = fusion.group_strengths(c.findings, 0.2)
    assert s["intent"] == pytest.approx(0.35 + 0.15 * 0.35)


def test_single_strong_group_goes_to_review_not_likely():
    st = {g: 0.0 for g in fusion.GROUPS}
    st["attachment"] = 1.0
    st["text_model"] = 0.2
    d = fusion.decide(_fi(strengths=st, model_score=0.2))
    assert d["verdict"] == "SUSPICIOUS_REVIEW"


def test_uncorroborated_text_model_is_uncertainty_not_review():
    st = {g: 0.0 for g in fusion.GROUPS}
    st["text_model"] = 0.75
    fi = _fi(strengths=st, model_score=0.75)
    d = fusion.decide(fi)
    assert d["verdict"] == "NO_STRONG_INDICATORS"
    assert any("text model leans malicious" in r for r in fusion.uncertainty(fi, d)["reasons"])


def test_high_impact_request_with_unverified_identity_goes_to_review():
    d = fusion.decide(_fi(high_impact_actions=["change_bank_details"]))
    assert d["verdict"] == "SUSPICIOUS_REVIEW"
    assert fusion.decide(_fi(high_impact_actions=["change_bank_details"], identity_verified=True))["verdict"] == "NO_STRONG_INDICATORS"


def test_parse_failure_and_short_text_are_insufficient():
    assert fusion.decide(_fi(parse_ok=False))["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert fusion.decide(_fi(word_count=3))["verdict"] == "INSUFFICIENT_EVIDENCE"


def test_every_finding_has_provenance(analyze):
    r = analyze(eml({"From": '"CFO" <c@gmail.com>', "Reply-To": "x@protonmail.com", "Subject": "Wire"},
                    "Keep this confidential and process the wire transfer today. https://pay.test/x"))
    for f in r["findings"]:
        assert f["finding_id"] and f["source_location"] and f["method"] in ("rule", "model", "provider") and f["version"]
        assert f["status"] in ("observed", "inferred", "unavailable") and f["timestamp"]
        if f["status"] == "inferred" and f["category"] == "intent.zero_link_bec":
            assert f["related_finding_ids"]
    ids = {f["finding_id"] for f in r["findings"]}
    for n in r["reconstruction"]["nodes"]:
        assert set(n["evidence"]) <= ids
    for e in r["reconstruction"]["edges"]:
        assert set(e["evidence"]) <= ids


def test_benign_mail_gets_insufficient_story(analyze):
    r = analyze(eml({"From": "a@phishdna-demo.local", "Subject": "Lunch"}, "Want to grab lunch at 12:30 today with the team?"),
                org_domains_override=["phishdna-demo.local"])
    assert not r["reconstruction"]["has_attack_story"]
    assert "Insufficient evidence" in r["reconstruction"]["narrative"]
    assert r["reconstruction"]["attack_mapping"] == []


def test_score_is_bounded_and_monotonic():
    lo = fusion.risk_score({g: 0.0 for g in fusion.GROUPS})
    hi = fusion.risk_score({g: 1.0 for g in fusion.GROUPS})
    assert lo == 0 and 0 < hi <= 100
    rng = np.random.default_rng(0)
    for _ in range(50):
        s = {g: float(rng.random()) for g in fusion.GROUPS}
        g = fusion.GROUPS[int(rng.integers(len(fusion.GROUPS)))]
        s2 = {**s, g: min(1.0, s[g] + 0.2)}
        assert fusion.risk_score(s2) >= fusion.risk_score(s)
