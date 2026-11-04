#!/usr/bin/env python3
"""
inspector.py - Ephemeral Playwright Detonation Engine for Phish&Chips.
Runs strictly inside the isolated phishchips-sandbox container.
Outputs: /out/shot1.png, /out/shot2.png, /out/result.json
"""

import os
import sys
import json
import time
import re
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

TARGET_URL = os.getenv("TARGET_URL", "").strip()
SUBMIT_PASS = os.getenv("SUBMIT_PASS", "0").lower() in ("1", "true", "yes")
OUT_DIR = os.getenv("OUT_DIR", "/out")

if not TARGET_URL:
    print(json.dumps({"error": "TARGET_URL environment variable is required"}))
    sys.exit(1)

# Handle offline demo shortcut inside isolated sandbox
nav_url = TARGET_URL
if TARGET_URL in ("demo://fake-bank", "demo:fake-bank", "https://demo.phishchips/fake-bank"):
    nav_url = "file:///app/demo/bank_login.html"

os.makedirs(OUT_DIR, exist_ok=True)

result = {
    "url": TARGET_URL,
    "final_url": TARGET_URL,
    "redirect_chain": [TARGET_URL],
    "title": "",
    "text": "",
    "fields": {
        "password": 0,
        "otp_like": 0,
        "card_like": 0,
        "inputs": []
    },
    "form_actions": [],
    "external_domains": [],
    "blocked_events": [],
    "screenshots": [],
    "has_logo_or_icon": False,
    "tls_error": False,
    "submit_pass_executed": False,
    "post_submit_url": None,
    "error": None
}

def get_domain(u):
    try:
        parsed = urlparse(u)
        return parsed.netloc.split(":")[0].lower()
    except Exception:
        return ""

base_domain = get_domain(TARGET_URL)
external_domains_set = set()

with sync_playwright() as p:
    browser = None
    try:
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--no-zygote",
                "--single-process"
            ]
        )

        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 PhishChips/1.0",
            accept_downloads=False,
            ignore_https_errors=True
        )

        page = context.new_page()

        # Listen for download attempts and intercept
        def on_download(download):
            msg = f"Automatic file download blocked: {download.suggested_filename} ({download.url})"
            result["blocked_events"].append({"type": "download", "detail": msg})
            try:
                download.cancel()
            except Exception:
                pass

        page.on("download", on_download)

        # Listen for popup / new windows
        def on_popup(popup):
            msg = f"Unsolicited popup blocked: {popup.url}"
            result["blocked_events"].append({"type": "popup", "detail": msg})

        page.on("popup", on_popup)

        # Auto-dismiss dialogs / alerts
        page.on("dialog", lambda dialog: dialog.dismiss())

        # Collect external domains from all outgoing network requests
        def on_request(req):
            d = get_domain(req.url)
            if d and base_domain and d != base_domain:
                external_domains_set.add(d)

        page.on("request", on_request)

        # Track navigation redirect chain
        redirect_chain = [TARGET_URL]

        def on_response(res):
            if res.status in (301, 302, 303, 307, 308):
                loc = res.headers.get("location")
                if loc:
                    redirect_chain.append(loc)

        page.on("response", on_response)

        # Navigate with hard timeout (20s)
        try:
            resp = page.goto(nav_url, wait_until="load", timeout=20000)
            if resp and resp.status >= 400:
                result["http_status"] = resp.status
        except PlaywrightTimeoutError:
            result["error"] = "Navigation timed out (20s limit reached)"
        except Exception as ex:
            err_str = str(ex)
            if "CERT" in err_str.upper() or "SSL" in err_str.upper():
                result["tls_error"] = True
            result["error"] = f"Navigation error: {err_str}"

        # Wait briefly for dynamic JS and client-side rendering
        page.wait_for_timeout(2000)

        # Update final URL and redirect chain
        result["final_url"] = page.url
        if result["final_url"] not in redirect_chain:
            redirect_chain.append(result["final_url"])
        result["redirect_chain"] = redirect_chain

        # Capture primary screenshot
        shot1_path = os.path.join(OUT_DIR, "shot1.png")
        page.screenshot(path=shot1_path, full_page=False)
        result["screenshots"].append("shot1.png")

        # Scroll down slightly and capture secondary screenshot
        try:
            page.evaluate("window.scrollBy(0, 600)")
            page.wait_for_timeout(500)
            shot2_path = os.path.join(OUT_DIR, "shot2.png")
            page.screenshot(path=shot2_path, full_page=False)
            result["screenshots"].append("shot2.png")
        except Exception:
            pass

        # Extract DOM data
        try:
            result["title"] = page.title()
        except Exception:
            result["title"] = ""

        try:
            raw_text = page.evaluate("() => document.body ? document.body.innerText : ''")
            result["text"] = (raw_text or "").strip()[:5000]
        except Exception:
            result["text"] = ""

        # Check for logos / icons
        try:
            has_logo = page.evaluate("""() => {
                const imgs = Array.from(document.querySelectorAll('img, svg'));
                return imgs.some(el => {
                    const src = (el.src || el.getAttribute('class') || el.id || '').toLowerCase();
                    return src.includes('logo') || src.includes('brand') || src.includes('icon');
                });
            }""")
            result["has_logo_or_icon"] = bool(has_logo)
        except Exception:
            result["has_logo_or_icon"] = False

        # Extract forms and inputs
        try:
            extracted_forms = page.evaluate("""() => {
                const forms = Array.from(document.querySelectorAll('form'));
                const actions = forms.map(f => f.action).filter(Boolean);
                
                const allInputs = Array.from(document.querySelectorAll('input, select, textarea'));
                const inputs = allInputs.map(i => ({
                    type: (i.type || 'text').toLowerCase(),
                    name: i.name || '',
                    id: i.id || '',
                    placeholder: i.placeholder || '',
                    autocomplete: i.autocomplete || ''
                }));

                return { actions, inputs };
            }""")

            result["form_actions"] = extracted_forms.get("actions", [])
            inputs_list = extracted_forms.get("inputs", [])
            result["fields"]["inputs"] = inputs_list

            password_count = sum(1 for i in inputs_list if i["type"] == "password")
            
            otp_pattern = re.compile(r"(otp|code|pin|2fa|verification|passcode|token)", re.IGNORECASE)
            card_pattern = re.compile(r"(card|cvv|cvc|pan|expir|debit|credit)", re.IGNORECASE)

            otp_count = sum(1 for i in inputs_list if (
                otp_pattern.search(i.get("name", "")) or 
                otp_pattern.search(i.get("placeholder", "")) or 
                otp_pattern.search(i.get("id", ""))
            ))

            card_count = sum(1 for i in inputs_list if (
                card_pattern.search(i.get("name", "")) or 
                card_pattern.search(i.get("placeholder", "")) or 
                card_pattern.search(i.get("id", ""))
            ))

            result["fields"]["password"] = password_count
            result["fields"]["otp_like"] = otp_count
            result["fields"]["card_like"] = card_count

        except Exception as ex:
            print(f"Error parsing DOM inputs: {ex}", file=sys.stderr)

        # Pattern B: Human-approved second pass execution inside the sandbox
        if SUBMIT_PASS and (result["fields"]["password"] > 0 or result["fields"]["otp_like"] > 0 or len(result["fields"]["inputs"]) > 0):
            result["submit_pass_executed"] = True
            try:
                print("Pattern B: Executing fake data submission pass...", file=sys.stderr)
                # Fill dummy values into input fields
                page.evaluate("""() => {
                    const inputs = Array.from(document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])'));
                    inputs.forEach(input => {
                        const type = (input.type || '').toLowerCase();
                        const name = (input.name || '').toLowerCase();
                        const placeholder = (input.placeholder || '').toLowerCase();

                        if (type === 'password') {
                            input.value = 'DemoFakeP@ss99';
                        } else if (name.includes('otp') || placeholder.includes('otp') || name.includes('pin') || placeholder.includes('code')) {
                            input.value = '123456';
                        } else if (name.includes('card') || placeholder.includes('card') || name.includes('cvv')) {
                            input.value = '4111111111111111';
                        } else if (type === 'email' || name.includes('email') || name.includes('user') || name.includes('login') || placeholder.includes('user')) {
                            input.value = 'sandboxed_canary_user@test-example.com';
                        } else if (type === 'tel' || name.includes('phone') || name.includes('mobile')) {
                            input.value = '+919999999999';
                        } else {
                            input.value = 'FakeTestValue';
                        }
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                        input.dispatchEvent(new Event('change', { bubbles: true }));
                    });
                }""")

                page.wait_for_timeout(1000)

                # Attempt clicking submit button
                submitted = page.evaluate("""() => {
                    const btn = document.querySelector('button[type="submit"], input[type="submit"], button, .btn');
                    if (btn) {
                        btn.click();
                        return true;
                    }
                    return false;
                }""")

                if submitted:
                    page.wait_for_timeout(3000)
                    result["post_submit_url"] = page.url
                    shot_submit_path = os.path.join(OUT_DIR, "shot_after_submit.png")
                    page.screenshot(path=shot_submit_path, full_page=False)
                    result["screenshots"].append("shot_after_submit.png")
            except Exception as sub_ex:
                print(f"Error during dummy submission pass: {sub_ex}", file=sys.stderr)

    except Exception as e:
        result["error"] = str(e)
    finally:
        if browser:
            try:
                browser.close()
            except Exception:
                pass

        result["external_domains"] = sorted(list(external_domains_set))
        out_json_path = os.path.join(OUT_DIR, "result.json")
        with open(out_json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        print(json.dumps({
            "status": "completed",
            "final_url": result["final_url"],
            "screenshots": result["screenshots"],
            "error": result["error"]
        }))
