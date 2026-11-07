import pytest
from c2_hunter import extract_c2_intelligence

def test_telegram_bot_c2_detection():
    telemetry = {
        "url": "https://fake-bank-login.com",
        "exfiltration_channels": [
            {
                "channel": "telegram_bot",
                "destination": "https://api.telegram.org/bot7182940182:AAFakeTokenForTest/sendMessage?chat_id=12345678",
                "method": "POST"
            }
        ],
        "post_requests": [],
        "form_actions": ["https://evil-exfiltrator-test.com/steal"]
    }

    c2 = extract_c2_intelligence(telemetry)
    assert c2["has_exfiltration"] is True
    assert len(c2["detected_drops"]) >= 1
    
    tg_drop = next((d for d in c2["detected_drops"] if d["channel"] == "telegram_bot"), None)
    assert tg_drop is not None
    assert "7182940182" in tg_drop["details"]
    assert tg_drop["severity"] == "CRITICAL"

def test_discord_webhook_c2_detection():
    telemetry = {
        "url": "https://stealth-portal.net",
        "exfiltration_channels": [
            {
                "channel": "discord_webhook",
                "destination": "https://discord.com/api/webhooks/1234567890/ABCDEF123456",
                "method": "POST"
            }
        ],
        "post_requests": [],
        "form_actions": []
    }

    c2 = extract_c2_intelligence(telemetry)
    assert c2["has_exfiltration"] is True
    assert any("discord" in d["channel"].lower() for d in c2["detected_drops"])

def test_clean_benign_no_c2():
    telemetry = {
        "url": "https://wikipedia.org",
        "exfiltration_channels": [],
        "post_requests": [],
        "form_actions": ["https://www.wikipedia.org/search-redirect.php"]
    }

    c2 = extract_c2_intelligence(telemetry)
    assert c2["has_exfiltration"] is False
    assert len(c2["detected_drops"]) == 0

