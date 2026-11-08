import json
from pathlib import Path
import pytest
from takedown import generate_takedown_package
import db

def test_takedown_with_re_artifacts():
    scan_data = {
        "job_id": "test-job-re",
        "target_url": "https://malicious-patch.com/login",
        "pretending_to_be": "State Bank of India",
        "confidence": 0.98,
        "reasons": ["High-entropy packed executable detected."],
        "re_intelligence": {
            "has_disassembly": True,
            "attribution_summary": "Malware dropper detected",
            "artifacts": [
                {
                    "name": "SBI_Patch.exe",
                    "type": "pe",
                    "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "entropy": 7.45,
                    "is_packed": True,
                    "capabilities": ["process_injection", "c2_communication"],
                    "size_bytes": 40960
                }
            ]
        }
    }
    pkg = generate_takedown_package(scan_data)
    assert "[REVERSE-ENGINEERED MALWARE & EVASION ARTIFACTS]:" in pkg["abuse_letter_text"]
    assert "SBI_Patch.exe" in pkg["abuse_letter_text"]
    assert "process_injection" in pkg["abuse_letter_text"]
    
    stix = pkg["stix_bundle"]
    file_objs = [o for o in stix["objects"] if o["type"] == "file"]
    rel_objs = [o for o in stix["objects"] if o["type"] == "relationship"]
    assert len(file_objs) == 1
    assert file_objs[0]["name"] == "SBI_Patch.exe"
    assert file_objs[0]["hashes"]["SHA-256"] == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    assert len(rel_objs) == 1
    assert rel_objs[0]["relationship_type"] == "drops"

def test_db_persistence_re_intelligence(tmp_path, monkeypatch):
    test_db_path = tmp_path / "test_phishchips.db"
    monkeypatch.setattr(db, "DB_PATH", test_db_path)
    db.init_db()

    job_id = "test-re-db-job"
    re_payload = {
        "has_disassembly": True,
        "attribution_summary": "In-memory WASM evasion detected",
        "artifacts": [
            {
                "name": "in_memory_evasion.wasm",
                "type": "wasm",
                "sha256": "1122334455667788990011223344556677889900112233445566778899001122",
                "entropy": 5.82,
                "is_packed": False,
                "capabilities": ["stealth_evasion"],
                "size_bytes": 1024
            }
        ]
    }

    db.save_scan(
        job_id=job_id,
        target_url="https://fake-bank-wasm.com",
        status="done",
        verdict="SCAM",
        confidence=0.99,
        threat_type="malware_delivery",
        verdict_class="malicious",
        re_intelligence=re_payload
    )

    retrieved = db.get_scan_by_id(job_id)
    assert retrieved is not None
    assert retrieved["re_intelligence"]["has_disassembly"] is True
    assert retrieved["re_intelligence"]["artifacts"][0]["name"] == "in_memory_evasion.wasm"

    recent = db.get_recent_scans(limit=5)
    matching = [s for s in recent if s["job_id"] == job_id]
    assert len(matching) == 1
    assert matching[0]["re_intelligence"]["attribution_summary"] == "In-memory WASM evasion detected"
