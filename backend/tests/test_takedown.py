import pytest
from takedown import generate_takedown_package

def test_generate_takedown_package():
    scan_data = {
        "job_id": "test_job_123",
        "target_url": "https://evil-bank-verify.com/login",
        "verdict": "SCAM",
        "verdict_class": "malicious",
        "confidence": 0.99,
        "threat_type": "credential_harvest",
        "pretending_to_be": "State Bank of India",
        "reasons": ["Impersonates official banking portal", "Steals OTP and password credentials"],
        "created_at": "2026-11-08T00:00:00Z",
        "c2_intelligence": {
            "has_exfiltration": True,
            "detected_drops": [
                {
                    "channel": "telegram_bot",
                    "title": "Telegram Bot Exfiltration Drop",
                    "destination": "https://api.telegram.org/bot7182940182:AAFake/sendMessage",
                    "details": "Telegram Bot API (Bot ID: 7182940182)"
                }
            ]
        }
    }

    pkg = generate_takedown_package(scan_data)
    assert pkg["domain"] == "evil-bank-verify.com"
    assert "abuse_contacts" in pkg and len(pkg["abuse_contacts"]) > 0
    assert "abuse_letter_text" in pkg
    assert "[URGENT ABUSE NOTICE]" in pkg["abuse_letter_text"]
    assert "evil-bank-verify.com" in pkg["abuse_letter_text"]
    assert "7182940182" in pkg["abuse_letter_text"]
    
    # STIX 2.1 validation
    assert "stix_bundle" in pkg
    stix = pkg["stix_bundle"]
    assert stix["type"] == "bundle"
    assert any(obj["type"] == "indicator" for obj in stix.get("objects", []))

