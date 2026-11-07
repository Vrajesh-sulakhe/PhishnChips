import io
import tarfile
from pathlib import Path
from fastapi.testclient import TestClient
import main
import db
import scanner

def test_evidence_tarball_and_takedown_api(tmp_path, monkeypatch):
    db.init_db()
    c = TestClient(main.app)

    # Set up mock evidence directory
    job_id = "test_suite_job1"
    evidence_dir = tmp_path / "evidence" / job_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "shot1.png").write_bytes(b"\x89PNG\r\n\x1a\nfakeimage")
    (evidence_dir / "telemetry.json").write_text('{"target_url": "https://phish.target"}')

    # Patch EVIDENCE_DIR in main, scanner, and forensics
    monkeypatch.setattr(main, "EVIDENCE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(scanner, "EVIDENCE_DIR", tmp_path / "evidence")

    # Seed job in memory
    scanner.jobs[job_id] = {
        "job_id": job_id,
        "target_url": "https://phish.target/login",
        "status": "done",
        "screenshots": [f"/api/scan/{job_id}/shot/shot1.png"],
        "raw_result": {
            "target_url": "https://phish.target/login",
            "exfiltration_targets": [
                {"channel": "telegram_bot", "endpoint": "https://api.telegram.org/bot12345/sendMessage", "method": "POST"}
            ]
        },
        "verdict": {
            "verdict": "SCAM",
            "verdict_class": "malicious",
            "confidence": 0.99,
            "threat_source": "Tier 1: High-Confidence Behavioural Detection",
            "pretending_to_be": "Chase Bank",
            "threat_type": "credential_harvest",
            "reasons": ["Credential form submitted to unauthorized endpoint"]
        },
        "c2_intelligence": {
            "has_c2_exfiltration": True,
            "drop_destinations": [
                {
                    "channel_type": "telegram_bot",
                    "target_endpoint": "https://api.telegram.org/bot12345/sendMessage",
                    "identifier": "12345",
                    "risk_rating": "CRITICAL"
                }
            ],
            "attribution_summary": "Active credential siphon to Telegram Bot infrastructure."
        }
    }

    # Also save to DB
    db.save_scan(
        job_id=job_id,
        target_url="https://phish.target/login",
        status="done",
        verdict="SCAM",
        confidence=0.99,
        threat_source="Tier 1",
        screenshots=["shot1.png"],
        reasons=["Credential harvester"],
        pretending_to_be="Chase Bank",
        threat_type="credential_harvest",
        verdict_class="malicious",
        c2_intelligence=scanner.jobs[job_id]["c2_intelligence"]
    )

    # 1. Test GET /api/scan/{job_id}/evidence.tar.gz
    resp_tar = c.get(f"/api/scan/{job_id}/evidence.tar.gz")
    assert resp_tar.status_code == 200
    assert "gzip" in resp_tar.headers.get("content-type", "")
    assert f"DET-{job_id}-FORENSIC-LOCKER.tar.gz" in resp_tar.headers.get("content-disposition", "")

    # Verify tarball contents
    tar_stream = io.BytesIO(resp_tar.content)
    with tarfile.open(fileobj=tar_stream, mode="r:gz") as tar:
        names = tar.getnames()
        assert any("manifest.json" in n for n in names)
        assert any("shot1.png" in n for n in names)

    # 2. Test GET /api/scan/{job_id}/takedown
    resp_takedown = c.get(f"/api/scan/{job_id}/takedown")
    assert resp_takedown.status_code == 200
    data = resp_takedown.json()
    assert "abuse_letter" in data
    assert "stix_bundle" in data
    assert "abuse_contacts" in data
    assert "Chase Bank" in data["abuse_letter"]
    assert data["stix_bundle"]["type"] == "bundle"

    # 3. Test GET /api/scan/{job_id} status enrichment
    resp_status = c.get(f"/api/scan/{job_id}")
    assert resp_status.status_code == 200
    status_data = resp_status.json()
    assert status_data["c2_intelligence"]["has_c2_exfiltration"] is True
    assert status_data["c2_intelligence"]["drop_destinations"][0]["channel_type"] == "telegram_bot"

