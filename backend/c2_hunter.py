"""
c2_hunter.py - Attacker C2 & Credential Exfiltration Drop Hunter for Phish&Chips.
Analyzes telemetry from sandboxed detonation to identify and classify where threat actors
exfiltrate stolen credentials (e.g. Telegram Bots, Discord Webhooks, Rogue PHP Drop Endpoints).
"""

import re
from typing import Dict, Any, List
from urllib.parse import urlparse

_TG_BOT_RE = re.compile(r"api\.telegram\.org/bot([0-9]+):[A-Za-z0-9_-]+", re.IGNORECASE)
_DISCORD_WH_RE = re.compile(r"discord(?:app)?\.com/api/webhooks/([0-9]+)/[A-Za-z0-9_-]+", re.IGNORECASE)

def extract_c2_intelligence(telemetry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses sandboxed network traffic and form targets to unmask the attacker's
    command-and-control (C2) or exfiltration infrastructure.
    """
    detected_drops: List[Dict[str, Any]] = []
    base_url = telemetry.get("url") or ""
    base_domain = ""
    try:
        base_domain = urlparse(base_url).netloc.split(":")[0].lower()
    except Exception:
        pass

    # 1. Parse explicit exfiltration channels identified by Playwright
    for item in telemetry.get("exfiltration_channels", []):
        dest = item.get("destination") or item.get("url") or ""
        ch = item.get("channel") or ""

        if ch == "telegram_bot" or "api.telegram.org/bot" in dest.lower():
            tg_match = _TG_BOT_RE.search(dest)
            bot_id = tg_match.group(1) if tg_match else "Unknown"
            detected_drops.append({
                "channel": "telegram_bot",
                "title": "Telegram Bot Exfiltration Drop",
                "destination": dest,
                "details": f"Telegram Bot API (Bot ID: {bot_id})",
                "severity": "CRITICAL",
                "recommendation": f"Report Bot ID {bot_id} to Telegram Abuse (abuse@telegram.org)"
            })
        elif ch == "discord_webhook" or "discord.com/api/webhooks" in dest.lower() or "discordapp.com/api/webhooks" in dest.lower():
            wh_match = _DISCORD_WH_RE.search(dest)
            wh_id = wh_match.group(1) if wh_match else "Unknown"
            detected_drops.append({
                "channel": "discord_webhook",
                "title": "Discord Webhook Exfiltration Drop",
                "destination": dest,
                "details": f"Discord Webhook (ID: {wh_id})",
                "severity": "CRITICAL",
                "recommendation": f"Report Webhook {wh_id} to Discord Trust & Safety (trustandsafety@discord.com)"
            })
        elif ch == "c2_drop_endpoint" or any(k in dest.lower() for k in ("gate.php", "drop.php", "post.php", "steal")):
            detected_drops.append({
                "channel": "c2_drop_endpoint",
                "title": "Rogue PHP / C2 Exfiltration Receiver",
                "destination": dest,
                "details": f"External C2 POST endpoint: {dest[:100]}",
                "severity": "HIGH",
                "recommendation": "Submit domain for immediate registrar suspension"
            })

    # 2. Inspect external form actions
    form_actions = telemetry.get("form_actions", [])
    for action in form_actions:
        try:
            act_domain = urlparse(action).netloc.split(":")[0].lower()
            if act_domain and base_domain and act_domain != base_domain and not act_domain.endswith("." + base_domain):
                # Avoid duplicate entries if already caught
                if not any(d["destination"] == action for d in detected_drops):
                    detected_drops.append({
                        "channel": "external_form_action",
                        "title": "Cross-Domain Form Exfiltration",
                        "destination": action,
                        "details": f"Credentials submitted to unassociated domain: {act_domain}",
                        "severity": "HIGH",
                        "recommendation": f"Issue abuse takedown notice to hosting provider for {act_domain}"
                    })
        except Exception:
            pass

    has_exfil = len(detected_drops) > 0
    summary = "No unauthorized credential exfiltration channels detected."
    if has_exfil:
        channels_str = ", ".join(d["title"] for d in detected_drops[:2])
        summary = f"Active threat infrastructure unmasked: {channels_str}."

    return {
        "has_exfiltration": has_exfil,
        "total_channels": len(detected_drops),
        "detected_drops": detected_drops,
        "summary": summary
    }

