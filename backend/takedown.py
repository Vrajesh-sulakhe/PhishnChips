"""
takedown.py - Automated Abuse Takedown Notice & STIX 2.1 Threat Intel Generator.
Generates legally compliant abuse notices for registrars/CDNs and standard STIX 2.1
JSON bundles for enterprise SIEM ingestion.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from urllib.parse import urlparse

def generate_takedown_package(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs an automated takedown package containing an RFC-compliant abuse notice
    and a STIX 2.1 IoC JSON bundle based on detonation forensics.
    """
    target_url = scan_data.get("target_url") or ""
    domain = ""
    try:
        domain = urlparse(target_url).netloc.split(":")[0].lower()
    except Exception:
        domain = target_url

    c2_info = scan_data.get("c2_intelligence") or {}
    detected_drops = c2_info.get("detected_drops") or []
    re_info = scan_data.get("re_intelligence") or {}
    re_artifacts = re_info.get("artifacts") or []
    pretending_to_be = scan_data.get("pretending_to_be") or "Legitimate Organization / Financial Institution"
    reasons = scan_data.get("reasons") or []
    confidence_pct = int((scan_data.get("confidence") or 0.95) * 100)
    job_id = scan_data.get("job_id") or "DET-0001"
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Determine abuse contacts based on detected infrastructure
    abuse_contacts: List[str] = []
    for drop in detected_drops:
        if drop.get("channel") == "telegram_bot":
            abuse_contacts.append("abuse@telegram.org")
        elif drop.get("channel") == "discord_webhook":
            abuse_contacts.append("trustandsafety@discord.com")

    # Standard upstream cloud / registrar contacts
    abuse_contacts.extend([
        "abuse@cloudflare.com",
        "abuse@namecheap.com",
        "cert@cert-in.org.in" # Indian Computer Emergency Response Team
    ])
    # Remove duplicates preserving order
    abuse_contacts = list(dict.fromkeys(abuse_contacts))

    # 2. Format formal RFC 2822 Abuse Letter
    c2_evidence_lines = ""
    if detected_drops:
        c2_evidence_lines = "\n[CRITICAL THREAT ARTIFACTS / C2 DROPS]:\n" + "\n".join(
            f" - {d.get('title')}: {d.get('details')} (Target: {d.get('destination')})" for d in detected_drops
        )

    re_evidence_lines = ""
    if re_artifacts:
        re_evidence_lines = "\n[REVERSE-ENGINEERED MALWARE & EVASION ARTIFACTS]:\n" + "\n".join(
            f" - {a.get('name')} (Type: {a.get('type')}, SHA-256: {a.get('sha256')}, Entropy: {a.get('entropy')}, Packed: {a.get('is_packed')}, Capabilities: {', '.join(a.get('capabilities', []) or ['none'])})"
            for a in re_artifacts
        )

    reasons_bulleted = "\n".join(f" - {r}" for r in reasons) if reasons else " - Unauthorized credential harvesting form detected."

    abuse_letter_text = f"""Subject: [URGENT ABUSE NOTICE] Malicious Credential Harvesting Phishing Campaign on {domain}

Dear Trust & Safety / Abuse Escalation Team,

We are writing to submit urgent forensic evidence regarding an active, verified phishing and credential harvesting campaign operating on infrastructure under your purview:

[CAMPAIGN DETAILS]:
- Target URL: {target_url}
- Host Domain: {domain}
- Target Impersonated: {pretending_to_be}
- Detonation Time: {now_utc}
- Automated Forensics Confidence: {confidence_pct}%
- Phish&Chips Investigation ID: {job_id}
{c2_evidence_lines}
{re_evidence_lines}

[FORENSIC EVIDENCE]:
{reasons_bulleted}

This website violates acceptable use policies, international computer crime statutes, and poses an active threat to consumers and financial services. Headless Chromium sandboxing inside our isolated detonation facility confirmed that this host actively solicits user credentials and attempts unauthorized data exfiltration.

We formally request the immediate suspension of domain resolution and revocation of hosting resources for this malicious host.

Cryptographically hashed forensic evidence (DOM snapshots, network traces, and visual proof) has been archived and is available upon request.

Sincerely,
Phish&Chips Automated Cyber Threat Intelligence
Control Plane Host: Vultr Cloud Compute (BLR)
Support: security@phishchips.internal
"""

    # 3. Generate STIX 2.1 Threat Intel Bundle
    bundle_id = f"bundle--{uuid.uuid4()}"
    indicator_id = f"indicator--{uuid.uuid4()}"
    malware_id = f"malware--{uuid.uuid4()}"
    timestamp_iso = datetime.now(timezone.utc).isoformat()

    stix_bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "id": indicator_id,
                "spec_version": "2.1",
                "created": timestamp_iso,
                "modified": timestamp_iso,
                "name": f"Phishing site targeting {pretending_to_be}",
                "description": f"Verified credential harvesting portal on {domain} impersonating {pretending_to_be}.",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[url:value = '{target_url}' OR domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "valid_from": timestamp_iso,
                "confidence": confidence_pct
            },
            {
                "type": "malware",
                "id": malware_id,
                "spec_version": "2.1",
                "created": timestamp_iso,
                "modified": timestamp_iso,
                "name": f"Credential Harvester ({pretending_to_be} Impersonation)",
                "is_family": False,
                "malware_types": ["credential-harvester"]
            }
        ]
    }

    # Add STIX File and Relationship objects for quarantined malware/wasm artifacts
    for art in re_artifacts:
        file_id = f"file--{uuid.uuid4()}"
        stix_bundle["objects"].append({
            "type": "file",
            "id": file_id,
            "spec_version": "2.1",
            "name": art.get("name", "malware.bin"),
            "hashes": {
                "SHA-256": art.get("sha256", "")
            },
            "size": art.get("size_bytes", 0)
        })
        rel_id = f"relationship--{uuid.uuid4()}"
        stix_bundle["objects"].append({
            "type": "relationship",
            "id": rel_id,
            "spec_version": "2.1",
            "created": timestamp_iso,
            "modified": timestamp_iso,
            "relationship_type": "drops",
            "source_ref": malware_id,
            "target_ref": file_id
        })

    return {
        "domain": domain,
        "target_url": target_url,
        "pretending_to_be": pretending_to_be,
        "abuse_contacts": abuse_contacts,
        "abuse_letter_text": abuse_letter_text.strip(),
        "abuse_letter": abuse_letter_text.strip(),
        "stix_bundle": stix_bundle
    }
