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
    assert h["time_budget_seconds"] <= 20 and h["reputation_list_size"] > 5000 and "metrics" in h

