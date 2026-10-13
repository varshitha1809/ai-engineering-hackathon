import socket

import pytest

from .conftest import eml


def _persist(engine, raw):
    return engine.analyze(raw, "eml", persist=True, correlate=True)


def test_shared_url_creates_traceable_edge(engine):
    a = _persist(engine, eml({"From": "x@a.test", "Subject": "Doc"}, "Open https://shared-landing.test/p?id=1 now"))
    b = _persist(engine, eml({"From": "y@b.test", "Subject": "Other"}, "Different words entirely, see https://shared-landing.test/p?id=1"))
    edges = engine.db.all("SELECT * FROM campaign_edges WHERE edge_type='shared_url'")
    assert len(edges) == 1 and {edges[0]["src"], edges[0]["dst"]} == {a["id"], b["id"]}
    assert "shared-landing.test" in edges[0]["evidence_json"][0]["value"]
    camp = engine.db.all("SELECT * FROM campaigns")
    assert len(camp) == 1 and camp[0]["member_count"] == 2
    assert any(f["category"] == "campaign.related_messages" for f in b["findings"])  # earlier identification of related mail


def test_near_duplicate_messages_are_linked(engine):
    body = ("Dear customer, we were unable to deliver your package because of an incomplete address. Please contact the "
            "depot to arrange a new delivery slot this week. Reference number DPX-4471. Regards, Delivery team")
    _persist(engine, eml({"From": "a@one.test", "Subject": "Delivery"}, body))
    _persist(engine, eml({"From": "b@two.test", "Subject": "Delivery notice"}, body.replace("DPX-4471", "DPX-9921")))
    e = engine.db.all("SELECT * FROM campaign_edges WHERE edge_type='near_duplicate_content'")
    assert len(e) == 1 and e[0]["strength"] >= 0.5


def test_generic_words_do_not_create_campaign(engine):
    _persist(engine, eml({"From": "a@one.test", "Subject": "urgent"}, "Urgent: please verify your account details today, it is important."))
    _persist(engine, eml({"From": "b@two.test", "Subject": "verify"}, "Quarterly report attached. Please verify the figures urgently before Monday's board meeting."))
    strong = engine.db.all("SELECT * FROM campaign_edges WHERE strength >= 0.5")
    assert strong == []
    assert engine.db.all("SELECT * FROM campaigns") == []


def test_analysis_never_opens_network_connections(analyze, monkeypatch):
    def no_net(*a, **k):
        raise AssertionError("network access attempted during analysis")
    monkeypatch.setattr(socket, "create_connection", no_net)
    monkeypatch.setattr(socket.socket, "connect", no_net)
    r = analyze(eml({"From": "a@x.test", "Subject": "s"}, "Click https://example.com/login and http://192.0.2.1/x",
                    attachments=[("a.exe", "application/octet-stream", b"MZ")]))
    assert r["parsed"]["url_count"] == 2
    assert r["stage_status"]["urls"]["status"] == "ok"


def test_detector_failure_is_reported_not_silent(analyze, monkeypatch):
    from backend.app.analysis.detectors import links_attachments

    def broken(ctx):
        raise ValueError("boom")
    monkeypatch.setattr(links_attachments, "run_urls", broken)
    r = analyze(eml({"From": "a@x.test", "Subject": "s"}, "hello https://x.test"))
    assert r["stage_status"]["urls"]["status"] == "failed"
    assert any(f["category"] == "stage.urls_failed" for f in r["findings"])
    assert "stage failed: urls" in r["uncertainty"]["reasons"]


def test_audit_redaction_removes_secrets_and_emails():
    from backend.app.services.audit import redact
    out = redact("api_key=SUPERSECRET123 user bob@corp.example token: abc")
    assert "SUPERSECRET123" not in out and "bob@corp.example" not in out and "abc" not in out


@pytest.mark.parametrize("variant_t", ["case_punct", "zero_width", "homoglyph", "word_split", "paraphrase", "html_visibility"])
def test_variants_validate_and_preserve_label(variant_t):
    from backend.app.evaluation.benchmark import BenchmarkRunner
    from backend.app.evaluation.variants import make_variant
    suite = BenchmarkRunner(None, None).load_suite()
    base = next(c for c in suite["cases"] if c["id"] == ("inj-01" if variant_t == "html_visibility" else "cred-01"))
    v, note = make_variant(base, variant_t)
    assert v is not None, note
    assert v["label"] == base["label"] and v["base_id"] == base["id"] and "validated" in v["validation"]
    assert v["raw"] != base["raw"]
