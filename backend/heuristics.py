"""
heuristics.py - Explainable threat signals for Phish&Chips.

Signals are split by evidential strength:
  * HARD signals - physically observed in the sandbox (credential form posting off-site,
    covert download, off-apex redirect from a reputable origin, brand mismatch *with*
    credential capture, injected login overlay). Only these can support a malicious verdict.
  * SOFT signals - lexical/structural hints (TLD, shortener, '@', hop count, brand word on
    page, credential fields on an unknown site). These can raise "suspicious" at most and are
    never sufficient for "malicious" on their own.
"""

import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from reputation import apex_domain, is_reputable, is_user_content_host, same_site

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
        return (p.hostname or "").lower()
    except Exception:
        return ""


def is_domain_match(page_domain: str, allowed_domains: List[str]) -> bool:
    for allowed in allowed_domains:
        if page_domain == allowed or page_domain.endswith("." + allowed):
            return True
    return False


_BRAND_PATTERNS = {
    name: re.compile(r"(?<![a-z0-9])(?:" + "|".join(re.escape(k) for k in info["keywords"]) + r")(?![a-z0-9])")
    for name, info in BRAND_CATALOG.items()
}


def _brand_in_head(title: str, text: str, pattern: "re.Pattern") -> bool:
    """Brand must appear as a whole word in the title or the opening of the visible text."""
    return bool(pattern.search(title) or pattern.search(text[:800]))


def _form_has_credentials(form: Dict[str, Any]) -> bool:
    return bool(form.get("has_password") or form.get("has_otp") or form.get("has_card"))


def evaluate_heuristics(result_data: Dict[str, Any]) -> Dict[str, Any]:
    """Compute explainable signals. Returns legacy keys plus `hard_signals` / `soft_signals`."""
    final_url = result_data.get("final_url", "") or ""
    requested_url = result_data.get("url", "") or final_url
    final_domain = extract_domain(final_url)
    final_apex = apex_domain(final_domain)
    title = (result_data.get("title") or "").lower()
    text = (result_data.get("text") or "").lower()
    fields = result_data.get("fields", {}) or {}
    password_count = fields.get("password", 0)
    otp_count = fields.get("otp_like", 0)
    card_count = fields.get("card_like", 0)
    inputs = fields.get("inputs", []) or []
    redirect_chain = result_data.get("redirect_chain", []) or []
    form_actions = result_data.get("form_actions", []) or []
    forms = result_data.get("forms", []) or []
    blocked_events = result_data.get("blocked_events", []) or []
    mutations = result_data.get("dom_mutations", []) or []
    post_requests = result_data.get("post_requests", []) or []
    has_credentials = (password_count + otp_count + card_count) > 0

    reputable_landing = is_reputable(final_url)
    reputable_origin = is_reputable(requested_url)

    hard: List[Dict[str, Any]] = []
    soft: List[Dict[str, Any]] = []
    reasons: List[str] = []
    indicators: List[str] = []
    pretending_to_be: Optional[str] = None
    asks_for: List[str] = []

    def add(bucket, weight, code, indicator, reason=None):
        bucket.append({"code": code, "weight": weight, "indicator": indicator})
        indicators.append(indicator)
        if reason:
            reasons.append(reason)

    # Asks-for tagging
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

    # --- Brand mimicry (skipped entirely for verified reputable apex that is not user-content) ---
    brand_hit = None
    if not reputable_landing:
        for brand_name, info in BRAND_CATALOG.items():
            if not _brand_in_head(title, text, _BRAND_PATTERNS[brand_name]):
                continue
            if is_domain_match(final_domain, info["domains"]):
                indicators.append(f"Verified Brand Domain: Belongs to {brand_name}")
                break
            brand_hit = brand_name
            break
    if brand_hit:
        pretending_to_be = brand_hit
        msg = f"Impersonates {brand_hit}, but is hosted on unofficial domain ({final_domain})."
        if has_credentials:
            add(hard, 70, "brand_mismatch_credentials", f"Brand Impersonation: {brand_hit} mismatch on {final_domain}", msg)
        else:
            add(soft, 25, "brand_word_mismatch", f"Brand mention without official domain: {brand_hit}", None)

    # --- Credential capture sending data off-site (per-form when available) ---
    exfil_hosts: List[str] = []
    if forms:
        for f in forms:
            act = extract_domain(f.get("action", ""))
            if _form_has_credentials(f) and act and not same_site(act, final_domain):
                if not (reputable_landing and is_reputable(f.get("action", ""))):
                    exfil_hosts.append(act)
    else:
        for action in form_actions:
            act = extract_domain(action)
            if has_credentials and act and final_domain and not same_site(act, final_domain):
                if not (reputable_landing and is_reputable(action)):
                    exfil_hosts.append(act)
    if exfil_hosts:
        add(hard, 70, "cross_origin_credential_form", f"Credential Form Exfiltration -> {exfil_hosts[0]}",
            f"Credential form submits to an external destination ({exfil_hosts[0]}).")

    for pr in post_requests:
        h = extract_domain(pr.get("url", ""))
        if has_credentials and h and not same_site(h, final_domain) and not is_reputable(pr.get("url", "")):
            add(hard, 70, "credential_exfil_request", f"Outbound POST to unverified host {h}",
                f"Page sent a POST request to an unverified external host ({h}) while collecting credentials.")
            break

    # --- Dynamic DOM anomalies ---
    for m in mutations:
        if m.get("kind") in ("login_modal", "credential_iframe") and not reputable_landing:
            add(hard, 60, "injected_login_ui", f"Dynamically injected {m.get('kind')}", "Login UI was injected into the page after load.")
            break

    # --- Covert downloads ---
    downloads = [e for e in blocked_events if e.get("type") == "download"]
    if downloads and not (reputable_landing and reputable_origin):
        add(hard, 55, "auto_download", "Malicious Delivery: Auto-download attempted",
            f"Attempted covert automatic file download inside sandbox: {downloads[0].get('detail', 'download')}")

    # --- Reverse Engineering / Malware Payloads ---
    wasm_artifacts = result_data.get("quarantined_wasm", [])
    if wasm_artifacts and not (reputable_landing and reputable_origin):
        add(hard, 65, "wasm_evasion_module", "Evasion Technique: Obfuscated WebAssembly runtime",
            f"Detected and quarantined {len(wasm_artifacts)} in-browser WebAssembly evasion module(s).")

    re_intel = result_data.get("re_intelligence") or {}
    for art in re_intel.get("artifacts", []):
        if art.get("is_packed"):
            add(hard, 70, "packed_binary_payload", f"Malware Delivery: High-entropy packed executable ({art.get('name')})",
                f"Binary entropy {art.get('entropy')} exceeds packed threshold; suspicious APIs: {', '.join(art.get('suspicious_apis', [])[:3])}")
            break

    # --- Open redirect / landing hijack from a reputable origin ---
    if reputable_origin and final_apex and not same_site(requested_url, final_url) and not reputable_landing:
        add(hard, 70, "off_apex_redirect", f"Reputable origin redirected to unverified apex {final_apex}",
            f"Trusted domain redirected to an unverified destination ({final_apex}).")

    # --- Soft signals ---
    if has_credentials and not brand_hit and not reputable_landing and not exfil_hosts:
        add(soft, 35, "credentials_on_unverified", "Credential Fields on Unverified Domain",
            f"Requests sensitive credentials ({', '.join(asks_for)}) on an unverified domain.")

    distinct_apexes = []
    for hop in redirect_chain:
        a = apex_domain(hop)
        if a and a not in distinct_apexes:
            distinct_apexes.append(a)
    if len(distinct_apexes) > 2 and not reputable_origin:
        add(soft, 15, "multi_apex_redirect", f"Evasion Technique: redirect through {len(distinct_apexes)} distinct domains",
            f"Navigated across {len(distinct_apexes)} distinct domains before landing.")

    parts = final_domain.split(".")
    if len(parts) > 1 and parts[-1] in SUSPICIOUS_TLDS and not reputable_landing:
        add(soft, 20, "risky_tld", f"Suspicious TLD: .{parts[-1]}", f"Hosted on a high-risk TLD (.{parts[-1]}).")
    if final_domain.startswith("xn--") or ".xn--" in final_domain:
        add(soft, 30, "punycode", "Punycode / Homograph lookalike domain", "Uses punycode/IDN characters that can disguise identity.")
    if final_domain in SHORTENERS:
        add(soft, 15, "shortener", f"URL Shortener link: {final_domain}")
    try:
        if "@" in (urlparse(final_url).netloc or ""):
            add(soft, 25, "userinfo_url", "URL Obfuscation with '@' syntax", "URL embeds credentials notation to obscure destination.")
    except ValueError:
        pass
    if is_user_content_host(final_url) and has_credentials:
        add(soft, 30, "credentials_on_ugc_host", "Credential capture on multi-tenant hosting platform")
    age = (result_data.get("domain_intel") or {}).get("age_days")
    if age is not None and age < 30 and not reputable_landing:
        add(soft, 25, "young_domain", f"Domain registered {age} days ago", f"Domain is only {age} days old.")

    hard_score = sum(s["weight"] for s in hard)
    soft_score = sum(s["weight"] for s in soft)
    score = min(100, hard_score + soft_score)

    if hard and hard_score + soft_score >= 65:
        verdict = "SCAM"
    elif hard or soft_score >= 35:
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
        "indicators": indicators,
        "hard_signals": hard,
        "soft_signals": soft,
    }
