#!/usr/bin/env python3
"""
build_golden.py - Deterministic golden regression dataset (500 benign + 500 phishing).

IMPORTANT - what this dataset is and is not:
  These are *synthetic sandbox-telemetry fixtures* (the same JSON the Playwright inspector
  emits), generated from realistic templates with a fixed seed. Benign apex domains are the
  real Tranco top list; phishing hostnames are fabricated lookalikes. No real malware or live
  phishing kits are stored in the repo. They exercise the *decision pipeline*; they do NOT
  prove real-world accuracy. For live containerised verification run:
      python tests/golden/run_golden.py --live urls.csv      (label,url per line)

Usage: python tests/golden/build_golden.py   -> writes benign.jsonl and phish.jsonl
"""

import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from reputation import USER_CONTENT_HOSTS, _load_reputable  # noqa: E402

SEED = 1337
rng = random.Random(SEED)

BRAND_WORDS = ["apple", "amazon", "microsoft", "paypal", "google", "netflix", "sbi", "hdfc", "paytm", "icici", "flipkart", "outlook"]
PHISH_BRANDS = {
    "State Bank of India": ("SBI Online Banking - Secure Login", "sbi-kyc", ["sbi", "onlinesbi"]),
    "HDFC Bank": ("HDFC Bank NetBanking Login", "hdfc-secure", ["hdfc"]),
    "Paytm": ("Paytm KYC Update Required", "paytm-kyc", ["paytm"]),
    "PayPal": ("PayPal - Log in to your account", "paypal-verify", ["paypal"]),
    "Microsoft": ("Sign in to your Microsoft account", "microsoft-login", ["microsoft"]),
    "Google Pay / Google": ("Google Account sign in", "google-signin", ["google account"]),
    "Netflix": ("Netflix - Update payment method", "netflix-billing", ["netflix"]),
    "Amazon": ("Amazon Sign-In", "amazon-secure", ["amazon"]),
    "Apple": ("Apple ID - Verify your account", "apple-id-verify", ["apple id"]),
    "Income Tax Department": ("Income Tax Refund Claim", "incometax-refund", ["income tax"]),
}
BAD_TLDS = ["xyz", "top", "click", "work", "live", "buzz", "com", "net", "info", "online", "site"]
SLUGS = ["login", "verify", "secure", "update", "account", "support", "id", "portal"]


def empty(url, final, title, text, chain=None):
    return {
        "url": url, "final_url": final, "redirect_chain": chain or [url, final], "title": title, "text": text,
        "fields": {"password": 0, "otp_like": 0, "card_like": 0, "inputs": []},
        "form_actions": [], "forms": [], "iframes": [], "dom_mutations": [], "post_requests": [],
        "external_domains": [], "blocked_events": [], "screenshots": ["shot1.png"], "error": None,
    }


def add_form(t, action, password=False, otp=False, card=False, extra_inputs=()):
    inputs = [{"type": "text", "name": "user", "id": "", "placeholder": "", "autocomplete": ""}]
    if password:
        inputs.append({"type": "password", "name": "pass", "id": "", "placeholder": "", "autocomplete": ""})
        t["fields"]["password"] += 1
    if otp:
        inputs.append({"type": "text", "name": "otp", "id": "", "placeholder": "OTP", "autocomplete": ""})
        t["fields"]["otp_like"] += 1
    if card:
        inputs.append({"type": "text", "name": "card_number", "id": "", "placeholder": "Card number", "autocomplete": ""})
        t["fields"]["card_like"] += 1
    inputs.extend(extra_inputs)
    t["fields"]["inputs"].extend(inputs)
    t["form_actions"].append(action)
    t["forms"].append({"action": action, "method": "post", "input_count": len(inputs),
                       "has_password": password, "has_otp": otp, "has_card": card})


def rand_name(n=8):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n))


def benign_samples():
    pool = sorted(d for d in _load_reputable() if d not in USER_CONTENT_HOSTS and d.count(".") == 1)[:3000]
    rng.shuffle(pool)
    out = []
    # 1) 200 reputable apex pages: brand words in text, www/locale redirects, CDNs, long edit query strings
    for apex in pool[:200]:
        kind = rng.choice(["plain", "edit_query", "donate", "multi_hop", "brandwords", "search"])
        base = f"https://{apex}/"
        final = f"https://www.{apex}/"
        url = base
        chain = [base, final]
        if kind == "edit_query":
            url = f"https://{apex}/w/index.php?title=Main_Page&action=edit&section=new&oldid={rng.randint(1,9999999)}&veaction=edit&preload=Template:{rand_name(30)}"
            final = url.replace("https://", "https://www.", 1)
            chain = [url, final]
        if kind == "multi_hop":
            chain = [f"http://{apex}/", f"https://{apex}/", final, final + "en/"]
            final = final + "en/"
        t = empty(url, final, apex.split(".")[0].title(),
                  "Welcome. " + (" ".join(rng.sample(BRAND_WORDS, 5)) if kind == "brandwords" else "Free encyclopedia of information.") +
                  " Download on the App Store. Get it on Google Play. Powered by Microsoft Azure.", chain)
        t["external_domains"] = sorted({f"cdn.{apex}", "fonts.googleapis.com", "upload.wikimedia.org", "www.googletagmanager.com"})
        if kind == "donate":
            add_form(t, f"https://donate.{apex}/submit")
        if kind == "search":
            add_form(t, f"https://{apex}/search")
        out.append({"id": f"benign-ref-{len(out):03d}", "category": "reputable_apex", "sample": t})
    # 2) 100 gov / edu / university portals
    suffixes = ["gov", "edu", "gov.uk", "ac.uk", "gov.in", "nic.in", "ac.in", "edu.au", "gov.au", "mil"]
    for i in range(100):
        host = f"{rand_name(7)}.{rng.choice(suffixes)}"
        t = empty(f"https://{host}/", f"https://www.{host}/", "Official Portal", "Citizen services. Income tax, Aadhaar, passport and student admissions information.")
        if i % 3 == 0:
            add_form(t, f"https://www.{host}/login", password=True)
        out.append({"id": f"benign-gov-{i:03d}", "category": "gov_edu", "sample": t})
    # 3) 100 login portals on reputable apexes (password fields, same-site POST)
    for i, apex in enumerate(pool[200:300]):
        final = f"https://accounts.{apex}/login"
        t = empty(f"https://{apex}/login", final, f"Sign in - {apex}", "Sign in to your account. Forgot password? Create account.",
                  [f"https://{apex}/login", final])
        add_form(t, f"https://accounts.{apex}/session", password=True)
        out.append({"id": f"benign-login-{i:03d}", "category": "reputable_login", "sample": t})
    # 4) 100 unknown small-business pages (no credentials) -> Tier 2 path
    for i in range(100):
        host = f"{rand_name(9)}.{rng.choice(['com', 'org', 'in', 'co.uk', 'io'])}"
        t = empty(f"https://{host}/", f"https://{host}/", "Local Business - Home", "Opening hours, menu, contact us. Newsletter signup.")
        if i % 2 == 0:
            t["fields"]["inputs"].append({"type": "email", "name": "email", "id": "", "placeholder": "Email", "autocomplete": ""})
            t["forms"].append({"action": f"https://{host}/subscribe", "method": "post", "input_count": 1,
                               "has_password": False, "has_otp": False, "has_card": False})
            t["form_actions"].append(f"https://{host}/subscribe")
        out.append({"id": f"benign-unknown-{i:03d}", "category": "unknown_clean", "sample": t})
    return out


def phish_samples():
    out = []

    def lookalike(slug):
        return f"{slug}-{rng.choice(SLUGS)}{rng.randint(1,999)}.{rng.choice(BAD_TLDS)}"

    # 1) 150 credential harvesters
    for i in range(150):
        brand, (title, slug, _kw) = rng.choice(list(PHISH_BRANDS.items()))
        host = lookalike(slug)
        t = empty(f"https://{host}/", f"https://{host}/", title, f"{title}. Enter your user ID and password. Verify your account now.")
        add_form(t, rng.choice([f"https://{host}/post.php", f"https://{rand_name(8)}.{rng.choice(BAD_TLDS)}/collect.php"]),
                 password=True, otp=(i % 3 == 0), card=(i % 5 == 0))
        out.append({"id": f"phish-cred-{i:03d}", "category": "credential_harvest", "sample": t})
    # 2) 100 fake OAuth consent / SSO
    for i in range(100):
        brand = rng.choice(["Microsoft", "Google Pay / Google"])
        title = PHISH_BRANDS[brand][0]
        host = lookalike(PHISH_BRANDS[brand][1])
        t = empty(f"https://{host}/oauth2/authorize", f"https://{host}/oauth2/authorize", title,
                  f"{title}. An app wants access to your account. Sign in to continue. Password required.")
        add_form(t, f"https://{rand_name(8)}.{rng.choice(BAD_TLDS)}/token", password=True)
        t["post_requests"].append({"url": f"https://{rand_name(8)}.top/log", "method": "POST", "resource_type": "xhr"})
        out.append({"id": f"phish-oauth-{i:03d}", "category": "fake_oauth", "sample": t})
    # 3) 100 scareware / tech-support scams with covert download
    for i in range(100):
        host = f"{rng.choice(['virus-alert', 'pc-cleaner', 'windows-defender-warning', 'security-scan'])}{rng.randint(1,999)}.{rng.choice(BAD_TLDS)}"
        t = empty(f"https://{host}/", f"https://{host}/", "WARNING: Your computer is infected",
                  "Virus detected! Your system is infected. Call support immediately or download the cleaner now.")
        t["blocked_events"].append({"type": "download", "detail": f"Automatic file download blocked: cleaner.exe (https://{host}/cleaner.exe)"})
        out.append({"id": f"phish-scare-{i:03d}", "category": "scareware", "sample": t})
    # 4) 75 phishing hosted on user-content platforms (must never be fast-passed)
    ugc = ["storage.googleapis.com/{r}/index.html", "{r}.github.io", "sites.google.com/view/{r}", "{r}.firebaseapp.com", "{r}.web.app", "{r}.pages.dev"]
    for i in range(75):
        brand, (title, slug, _kw) = rng.choice(list(PHISH_BRANDS.items()))
        r = f"{slug}{rng.randint(1,9999)}"
        host_path = rng.choice(ugc).format(r=r)
        final = "https://" + host_path
        t = empty(final, final, title, f"{title}. Sign in with your password.")
        add_form(t, final.rsplit("/", 1)[0] + "/submit" if "/" in host_path else final + "/submit", password=True)
        t["forms"][0]["action"] = f"https://{rand_name(8)}.{rng.choice(BAD_TLDS)}/c.php"
        t["form_actions"] = [t["forms"][0]["action"]]
        out.append({"id": f"phish-ugc-{i:03d}", "category": "ugc_hosted", "sample": t})
    # 5) 75 open-redirect abuse: reputable origin -> phishing landing
    reputables = ["google.com", "microsoft.com", "linkedin.com", "facebook.com", "adobe.com", "dropbox.com", "paypal.com", "amazon.com"]
    for i in range(75):
        brand, (title, slug, _kw) = rng.choice(list(PHISH_BRANDS.items()))
        origin = rng.choice(reputables)
        host = lookalike(slug)
        landing = f"https://{host}/"
        start = f"https://{origin}/url?q={landing}&sa=D"
        t = empty(start, landing, title, f"{title}. Enter your password to continue.", [start, landing])
        add_form(t, f"https://{host}/p.php", password=True)
        out.append({"id": f"phish-openredir-{i:03d}", "category": "open_redirect", "sample": t})
    return out


def main():
    benign, phish = benign_samples(), phish_samples()
    assert len(benign) == 500 and len(phish) == 500, (len(benign), len(phish))
    for name, data in (("benign.jsonl", benign), ("phish.jsonl", phish)):
        with open(HERE / name, "w", encoding="utf-8") as fh:
            for row in data:
                fh.write(json.dumps(row, separators=(",", ":")) + "\n")
    print(f"wrote {len(benign)} benign, {len(phish)} phish (seed={SEED})")


if __name__ == "__main__":
    main()

