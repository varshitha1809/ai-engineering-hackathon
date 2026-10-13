"""End-to-end API tests against the real app, real model and an isolated SQLite database."""
import time

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app

from .conftest import eml


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


BEC = eml({"From": '"Dana Whitfield, CEO" <dana.ceo.office@gmail.com>', "Reply-To": "desk@protonmail.com",
           "Subject": "Confidential payment"},
          "Please keep this between us. Our supplier changed their bank details; process the wire transfer to the new "
          "account today. I'm in meetings all day so email only.\nAccount number: 5512 0087 4419")


def test_health_reports_model_and_db(client):
    h = client.get("/api/v1/health").json()
    assert h["api"] == "ok" and h["database"] == "ok" and h["model"]["status"] == "loaded"
    assert all("key" not in str(p).lower() or "missing" in str(p).lower() or "not configured" in str(p).lower() for p in h["providers"])


def test_paste_and_upload_paths_persist_and_detail_opens(client):
    r = client.post("/api/v1/analyze", data={"text": "Hi, the meeting is moved to Thursday at 3pm in room 4B. Thanks, Priya"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["stage_status"]["text_model"]["status"] == "ok" and d["model"]["model_version"].startswith("textclf-")
    r2 = client.post("/api/v1/analyze", files={"file": ("bec.eml", BEC, "message/rfc822")})
    assert r2.status_code == 200
    bec = r2.json()
    assert bec["verdict"] in ("LIKELY_PHISHING", "SUSPICIOUS_REVIEW") and bec["case"] is not None
    got = client.get(f"/api/v1/analyses/{bec['id']}").json()
    assert got["id"] == bec["id"] and got["findings"] and got["reconstruction"]["nodes"]
    assert any(a["id"] == bec["id"] for a in client.get("/api/v1/analyses").json()["items"])


def test_validation_errors_are_explicit(client):
    assert client.post("/api/v1/analyze", data={"text": "   "}).status_code == 422
    assert client.post("/api/v1/analyze").status_code == 422
    assert client.post("/api/v1/analyze", files={"file": ("x.pdf", b"%PDF", "application/pdf")}).status_code == 415
    assert client.post("/api/v1/analyze", files={"file": ("x.msg", b"\xd0\xcf", "application/vnd.ms-outlook")}).status_code == 415
    big = b"x" * (5 * 1024 * 1024 + 10)
    assert client.post("/api/v1/analyze", files={"file": ("big.eml", big, "message/rfc822")}).status_code == 413
    assert client.get("/api/v1/analyses/A-NOPE").status_code == 404


def test_batch_isolates_failures(client):
    csv = b"subject,body\nInvoice,Please pay the attached invoice\nHello,See you at lunch tomorrow at the usual place\n"
    r = client.post("/api/v1/analyze/batch", files=[("files", ("a.csv", csv, "text/csv")), ("files", ("b.eml", BEC, "message/rfc822")),
                                                     ("files", ("c.pdf", b"%PDF", "application/pdf"))]).json()
    assert r["summary"]["total"] == 4 and r["summary"]["ok"] == 3 and r["summary"]["failed"] == 1


def test_case_actions_feedback_and_audit_persist(client):
    a = client.post("/api/v1/analyze", files={"file": ("bec.eml", BEC, "message/rfc822")}).json()
    cid = a["case"]["id"]
    r = client.patch(f"/api/v1/cases/{cid}", json={"action": "quarantine"})
    assert r.status_code == 409  # high-impact action needs explicit confirmation
    r = client.patch(f"/api/v1/cases/{cid}", json={"action": "quarantine", "confirm": True}).json()
    assert any("sandbox action" in m for m in r["messages"])
    r = client.patch(f"/api/v1/cases/{cid}", json={"action": "report_phishing", "note": "confirmed by finance"}).json()
    assert r["status"] == "in_review" and r["notes_json"][-1]["text"] == "confirmed by finance"
    d = client.get(f"/api/v1/analyses/{a['id']}").json()
    assert d["local_state"].startswith("quarantined") and d["feedback"][0]["label"] == "confirmed_phishing"
    assert d["original"]["verdict"] == a["verdict"]  # original prediction stays immutable
    audit = client.get(f"/api/v1/audit?target={cid}").json()
    assert {"case.quarantine", "case.report_phishing"} <= {e["action"] for e in audit}
    assert client.get("/api/v1/indicators?review_status=pending_review").json()["items"]


def test_report_exports(client):
    a = client.post("/api/v1/analyze", files={"file": ("bec.eml", BEC, "message/rfc822")}).json()
    md = client.get(f"/api/v1/analyses/{a['id']}/report?format=md")
    assert md.status_code == 200 and "analyst report" in md.text and "policy risk score, not a probability" in md.text
    assert "Account number: 5512" not in md.text  # full body is not exported, only evidence excerpts
    assert client.get(f"/api/v1/analyses/{a['id']}/report?format=csv").text.startswith("analysis_id,finding_id")
    assert client.get(f"/api/v1/analyses/{a['id']}/report?format=json").json()["id"] == a["id"]


def test_demo_seed_builds_justified_campaigns_and_rescore(client):
    r = client.post("/api/v1/demo/seed").json()
    assert len(r["results"]) == 15
    camps = client.get("/api/v1/campaigns").json()["items"]
    types = {t for c in camps for t in c["summary_json"]["edge_types"]}
    assert {"shared_url", "shared_reply_to", "shared_attachment_hash", "same_impersonated_identity"} <= types
    benign = [x["id"] for x in r["results"] if x["file"].startswith(("12-", "13-"))]
    members = {m["id"] for c in camps for m in client.get(f"/api/v1/campaigns/{c['id']}").json()["members"]}
    assert not (set(benign) & members)  # unrelated benign mail is not attached to any cluster
    stix = client.get(f"/api/v1/campaigns/{camps[0]['id']}/export?format=stix").json()
    assert stix["type"] == "bundle" and any(o["type"] == "campaign" for o in stix["objects"])
    # time-of-click re-score: mark the shared landing domain malicious and watch retained messages re-score
    res = client.post("/api/v1/indicators", json={"type": "domain", "value": "secure-docs-portal.test", "reputation": "malicious",
                                                  "source": "unit test"}).json()
    assert len(res["rescored"]) == 3 and all(x["status"] == "rescored" for x in res["rescored"])
    assert all(x["after"]["verdict"] == "LIKELY_PHISHING" for x in res["rescored"])


def test_benchmark_run_completes_with_real_metrics(client):
    rid = client.post("/api/v1/evaluations/run", json={"suite": "fixtures", "variants": False, "splits": ["dev"]}).json()["id"]
    for _ in range(240):
        run = client.get(f"/api/v1/evaluations/{rid}").json()
        if run["status"] in ("completed", "failed"):
            break
        time.sleep(0.5)
    assert run["status"] == "completed", run.get("error")
    m = run["metrics_json"]
    assert m["overall"]["hybrid"]["n"] == m["counts"]["labelled"] > 20
    assert set(m["ablation"]) >= {"full hybrid", "without text_model"}
    items = client.get(f"/api/v1/evaluations/{rid}/items").json()
    assert len(items) == m["counts"]["items"]
    one = client.get(f"/api/v1/evaluations/{rid}/items/{items[0]['item_id']}").json()
    assert "detail_json" in one


def test_replay_policy_whatif(client):
    r = client.post("/api/v1/replay", json={"mode": "policy", "review_threshold": 1, "likely_threshold": 2}).json()
    assert r["evaluated"] > 0 and "changed" in r and r["note"].startswith("Shadow")


def test_delete_removes_raw_and_evidence(client):
    a = client.post("/api/v1/analyze", data={"text": "Delete me: please verify your password at https://x.test now"}).json()
    assert client.delete(f"/api/v1/analyses/{a['id']}").status_code == 200
    assert client.get(f"/api/v1/analyses/{a['id']}").status_code == 404


def test_api_key_enforced_when_configured(client, monkeypatch):
    from backend.app import security
    from backend.app.config import Settings
    monkeypatch.setattr(security, "settings", Settings(api_key="test-key"))
    assert client.get("/api/v1/dashboard/summary").status_code == 401
    assert client.get("/api/v1/dashboard/summary", headers={"X-API-Key": "test-key"}).status_code == 200
    assert client.get("/api/v1/health").status_code == 200


def test_dashboard_counts_are_live(client):
    d = client.get("/api/v1/dashboard/summary").json()
    total = client.get("/api/v1/analyses?limit=1").json()["total"]
    assert d["totals"]["analyses"] == total and sum(d["risk_histogram"]) == total
