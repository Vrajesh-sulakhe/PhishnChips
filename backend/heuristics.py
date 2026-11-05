"""
heuristics.py - Explainable Threat Detection Heuristics for Phish&Chips.
Detects brand impersonation, deceptive credential harvesting, and suspicious redirects.
"""

from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple
import re

BRAND_CATALOG: Dict[str, Dict[str, Any]] = {
    "State Bank of India": {
        "keywords": ["sbi", "state bank of india", "onlinesbi", "yono"],
        "domains": ["onlinesbi.sbi", "sbi.co.in", "bank.sbi"]
    },
    "HDFC Bank": {
        "keywords": ["hdfc", "hdfc bank", "netbanking.hdfcbank"],
        "domains": ["hdfcbank.com"]
    },
    "ICICI Bank": {
        "keywords": ["icici", "icici bank", "infinity.icicibank"],
        "domains": ["icicibank.com"]
    },
    "Axis Bank": {
        "keywords": ["axis bank", "axisbank"],
        "domains": ["axisbank.com"]
    },
    "Paytm": {
        "keywords": ["paytm", "paytm payments bank", "paytm kyc"],
        "domains": ["paytm.com"]
    },
    "PhonePe": {
        "keywords": ["phonepe", "phone pe"],
        "domains": ["phonepe.com"]
    },
    "Google Pay / Google": {
        "keywords": ["google pay", "gpay", "google account", "gmail"],
        "domains": ["google.com", "google.co.in"]
    },
    "India Post": {
        "keywords": ["india post", "indiapost", "speed post", "dak seva"],
        "domains": ["indiapost.gov.in"]
    },
    "Income Tax Department": {
        "keywords": ["income tax", "incometax", "tax refund", "pan update", "e-filing"],
        "domains": ["incometax.gov.in"]
    },
    "UIDAI / Aadhaar": {
        "keywords": ["uidai", "aadhaar", "e-aadhaar", "aadhar kyc"],
        "domains": ["uidai.gov.in"]
    },
    "Amazon": {
        "keywords": ["amazon", "amazon prime", "amazon pay"],
        "domains": ["amazon.in", "amazon.com"]
    },
    "Flipkart": {
        "keywords": ["flipkart", "supercoins"],
        "domains": ["flipkart.com"]
    },
    "Netflix": {
        "keywords": ["netflix", "netflix membership"],
        "domains": ["netflix.com"]
    },
    "Microsoft": {
        "keywords": ["microsoft", "office365", "outlook", "onedrive"],
        "domains": ["microsoft.com", "live.com", "office.com"]
    },
    "Apple": {
        "keywords": ["apple", "icloud", "apple id"],
        "domains": ["apple.com", "icloud.com"]
    },
    "PayPal": {
        "keywords": ["paypal", "paypal account"],
        "domains": ["paypal.com"]
    }
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "loan", "gq", "tk", "ml", "cf", "ga",
    "fit", "live", "buzz", "surf", "rest", "cam", "quest", "cyou"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "rb.gy", "cutt.ly", "ow.ly"
}

def extract_domain(url: str) -> str:
    try:
        p = urlparse(url)
        return (p.netloc.split(":")[0] or "").lower()
    except Exception:
        return ""

def is_domain_match(page_domain: str, allowed_domains: List[str]) -> bool:
    for allowed in allowed_domains:
        if page_domain == allowed or page_domain.endswith("." + allowed):
            return True
    return False

def evaluate_heuristics(result_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes deterministic security signals, brand-vs-domain mismatch,
    credential harvesting indicators, and explainable reasons.
    """
    final_url = result_data.get("final_url", "")
    final_domain = extract_domain(final_url)
    title = (result_data.get("title") or "").lower()
    text = (result_data.get("text") or "").lower()
    fields = result_data.get("fields", {})
    password_count = fields.get("password", 0)
    otp_count = fields.get("otp_like", 0)
    card_count = fields.get("card_like", 0)
    inputs = fields.get("inputs", [])
    redirect_chain = result_data.get("redirect_chain", [])
    form_actions = result_data.get("form_actions", [])
    blocked_events = result_data.get("blocked_events", [])

    score = 0
    reasons: List[str] = []
    indicators: List[str] = []
    pretending_to_be: Optional[str] = None
    asks_for: List[str] = []

    # 1. Asks For Data Tagging
    if password_count > 0:
        asks_for.append("Password")
    if otp_count > 0:
        asks_for.append("OTP / Security PIN")
    if card_count > 0:
        asks_for.append("Card / Banking Details")
    if any(i.get("type") == "tel" or "phone" in i.get("name", "").lower() for i in inputs):
        asks_for.append("Phone Number")
    if any(i.get("type") == "email" or "email" in i.get("name", "").lower() for i in inputs):
        asks_for.append("Email Address")

    # 2. Brand-vs-Domain Mismatch Detection
    for brand_name, brand_info in BRAND_CATALOG.items():
        matched_kw = False
        for kw in brand_info["keywords"]:
            if kw in title or kw in text:
                matched_kw = True
                break

        if matched_kw:
            is_legit = is_domain_match(final_domain, brand_info["domains"])
            if not is_legit:
                pretending_to_be = brand_name
                score += 65
                msg = f"Impersonates {brand_name}, but is hosted on unofficial domain ({final_domain})."
                reasons.append(msg)
                indicators.append(f"Brand Impersonation: {brand_name} mismatch on {final_domain}")
                break
            else:
                # Legit domain of the brand
                indicators.append(f"Verified Brand Domain: Belongs to {brand_name}")

    # 3. Form Credential Targeting on Unverified Domains
    if (password_count > 0 or otp_count > 0 or card_count > 0) and not pretending_to_be:
        # Check if it's not a known brand
        score += 35
        reasons.append(f"Requests sensitive authentication credentials ({', '.join(asks_for)}) on an unverified domain.")
        indicators.append("Credential Harvest: Login / OTP fields present")

    # 4. Automatic Download Interceptions (Containment Moment Signal)
    downloads_blocked = [e for e in blocked_events if e.get("type") == "download"]
    if downloads_blocked:
        score += 50
        detail = downloads_blocked[0].get("detail", "Automatic file download triggered")
        reasons.append(f"Attempted covert automatic file download inside sandbox: {detail}")
        indicators.append("Malicious Delivery: Auto-download attempted")

    # 5. Form Actions Posting Across Domains
    for action in form_actions:
        action_domain = extract_domain(action)
        if action_domain and final_domain and action_domain != final_domain:
            score += 25
            reasons.append(f"Form submission exfiltrates data to external destination ({action_domain}).")
            indicators.append(f"Cross-Domain Form Exfiltration -> {action_domain}")
            break

    # 6. Redirect Traversals
    if len(redirect_chain) > 2:
        score += 15
        reasons.append(f"Navigated through a multi-hop redirection chain ({len(redirect_chain)} hops).")
        indicators.append(f"Evasion Technique: {len(redirect_chain)}-hop redirect chain")

    # 7. URL Domain Anomalies
    parts = final_domain.split(".")
    if len(parts) > 1:
        tld = parts[-1]
        if tld in SUSPICIOUS_TLDS:
            score += 20
            reasons.append(f"Registered on a high-risk TLD commonly associated with burner scam sites (.{tld}).")
            indicators.append(f"Suspicious TLD: .{tld}")

    if final_domain.startswith("xn--"):
        score += 30
        reasons.append("Uses Punycode / IDN lookalike characters to disguise domain identity.")
        indicators.append("Punycode / Homograph lookalike domain")

    if final_domain in SHORTENERS:
        score += 15
        indicators.append(f"URL Shortener link: {final_domain}")

    if "@" in final_url:
        score += 25
        reasons.append("URL contains '@' credential notation to obscure true destination.")
        indicators.append("URL Obfuscation with '@' syntax")

    # Clamp score
    score = min(100, max(0, score))

    # Verdict assignment
    if score >= 65:
        verdict = "SCAM"
    elif score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
        if not reasons:
            reasons.append("No credential harvesting forms, deceptive branding, or unauthorized downloads detected.")

    return {
        "heuristic_score": score,
        "heuristic_verdict": verdict,
        "pretending_to_be": pretending_to_be,
        "asks_for": asks_for,
        "reasons": reasons[:3],
        "indicators": indicators
    }

