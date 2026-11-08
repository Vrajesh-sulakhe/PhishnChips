from fastapi.testclient import TestClient

import main


def test_metrics_and_health_exposed():
    c = TestClient(main.app)
    m = c.get("/metrics")
    assert m.status_code == 200
    for name in ("phishchips_inference_latency_seconds", "phishchips_sandbox_timeouts_total",
                 "phishchips_schema_violations_total", "phishchips_scans_total", "phishchips_verdict_confidence"):
        assert name in m.text
    h = c.get("/api/health").json()
    assert h["time_budget_seconds"] <= 60 and h["reputation_list_size"] > 5000 and "metrics" in h


def test_recent_scans_and_reputation_healing():
    import db
    import uuid
    db.init_db()

    c = TestClient(main.app)
    test_email = f"wiki_{uuid.uuid4().hex[:6]}@phishchips.test"
    reg = c.post("/api/auth/register", json={
        "email": test_email,
        "password": "Password123!",
        "name": "Wiki Tester"
    })
    assert reg.status_code == 200
    user_id = reg.json()["user"]["id"]

    # Simulate legacy erroneous scan for wikipedia.org
    db.save_scan(
        job_id="test_wiki_legacy",
        target_url="https://wikipedia.org",
        status="done",
        user_id=user_id,
        verdict="SCAM",
        confidence=0.98,
        threat_source="Legacy test",
        threat_type="credential_harvest",
        verdict_class="malicious"
    )

    # Re-run init_db to exercise self-healing migration
    db.init_db()

    res = c.get("/api/scans/recent")
    assert res.status_code == 200
    scans = res.json().get("scans", [])
    wiki_scan = next((s for s in scans if s["job_id"] == "test_wiki_legacy"), None)
    assert wiki_scan is not None
    assert wiki_scan["verdict"] == "SAFE"
    assert wiki_scan["verdict_class"] == "benign"
    assert wiki_scan["confidence"] == 0.97
    assert wiki_scan["threat_type"] == "none"


