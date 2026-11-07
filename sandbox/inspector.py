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
NAV_TIMEOUT_MS = int(os.getenv("NAV_TIMEOUT_MS", "10000"))   # hard cap for the main navigation
SETTLE_MS = int(os.getenv("SETTLE_MS", "1500"))               # time for JS / delayed injections to run

# Anti-evasion: equivalent of puppeteer-extra-plugin-stealth's core evasions, applied via
# an init script so they run before any page script (cloaking kits probe these immediately).
STEALTH_JS = r"""
(() => {
  const def = (o, k, v) => { try { Object.defineProperty(o, k, { get: () => v, configurable: true }); } catch (e) {} };
  def(Navigator.prototype, 'webdriver', undefined);
  def(Navigator.prototype, 'languages', ['en-US', 'en']);
  def(Navigator.prototype, 'plugins', [1, 2, 3, 4, 5]);
  def(Navigator.prototype, 'hardwareConcurrency', 8);
  def(Navigator.prototype, 'deviceMemory', 8);
  if (!window.chrome) { window.chrome = { runtime: {}, loadTimes: function () {}, csi: function () {}, app: {} }; }
  const q = window.navigator.permissions && window.navigator.permissions.query;
  if (q) { window.navigator.permissions.query = (p) => p && p.name === 'notifications'
      ? Promise.resolve({ state: Notification.permission }) : q.call(window.navigator.permissions, p); }
  const patchGL = (proto) => { if (!proto) return; const g = proto.getParameter;
    proto.getParameter = function (p) { if (p === 37445) return 'Intel Inc.'; if (p === 37446) return 'Intel Iris OpenGL Engine'; return g.call(this, p); }; };
  patchGL(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
  patchGL(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
})();
"""

# Behavioural interception: record login UI injected after load (modals, overlays, foreign iframes).
MUTATION_JS = r"""
(() => {
  window.__pc_mutations = [];
  const note = (kind, detail) => { if (window.__pc_mutations.length < 20) window.__pc_mutations.push({ kind, detail: String(detail).slice(0, 200) }); };
  const inspect = (el) => {
    if (!(el instanceof Element)) return;
    const q = (sel) => el.matches && el.matches(sel) || el.querySelector && el.querySelector(sel);
    if (q('input[type=password]')) {
      const st = getComputedStyle(el);
      note(st.position === 'fixed' || st.position === 'absolute' ? 'login_modal' : 'login_form', el.tagName + '#' + (el.id || ''));
    }
    if (el.tagName === 'IFRAME') {
      try { const u = new URL(el.src, location.href); if (u.hostname !== location.hostname) note('credential_iframe', u.href); } catch (e) {}
    }
  };
  const start = () => new MutationObserver((muts) => muts.forEach((m) => m.addedNodes.forEach(inspect)))
      .observe(document.documentElement, { childList: true, subtree: true });
  if (document.documentElement) start(); else document.addEventListener('DOMContentLoaded', start);
})();
"""

_TWO_LABEL = {"co", "com", "org", "net", "gov", "edu", "ac", "nic", "or", "go", "ne"}

def apex_of(host):
    labels = (host or "").lower().split(".")
    if len(labels) >= 3 and labels[-2] in _TWO_LABEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

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
    "forms": [],
    "iframes": [],
    "dom_mutations": [],
    "post_requests": [],
    "redirect_chain_detail": [],
    "js_navigations": [],
    "external_domains": [],
    "blocked_events": [],
    "screenshots": [],
    "has_logo_or_icon": False,
    "tls_error": False,
    "submit_pass_executed": False,
    "post_submit_url": None,
    "exfiltration_channels": [],
    "stealth_applied": True,
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
                "--disable-blink-features=AutomationControlled",
                "--single-process"
            ]
        )

        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            accept_downloads=False,
            ignore_https_errors=True,
            locale="en-US",
            timezone_id="America/New_York",
            java_script_enabled=True,
        )
        context.add_init_script(STEALTH_JS)
        context.add_init_script(MUTATION_JS)

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

        # Collect external domains and detect exfiltration channels
        def on_request(req):
            d = get_domain(req.url)
            if d and base_domain and d != base_domain:
                external_domains_set.add(d)
            # Credential exfiltration candidates: state-changing requests leaving the site.
            if req.method in ("POST", "PUT") and d and apex_of(d) != apex_of(base_domain) and len(result["post_requests"]) < 20:
                result["post_requests"].append({"url": req.url[:300], "method": req.method, "resource_type": req.resource_type})

            url_lower = req.url.lower()
            if "api.telegram.org/bot" in url_lower and len(result["exfiltration_channels"]) < 10:
                result["exfiltration_channels"].append({
                    "channel": "telegram_bot",
                    "destination": req.url[:300],
                    "method": req.method
                })
            elif ("discord.com/api/webhooks" in url_lower or "discordapp.com/api/webhooks" in url_lower) and len(result["exfiltration_channels"]) < 10:
                result["exfiltration_channels"].append({
                    "channel": "discord_webhook",
                    "destination": req.url[:300],
                    "method": req.method
                })
            elif req.method in ("POST", "PUT") and any(k in url_lower for k in ("gate.php", "drop.php", "post.php", "steal", "receiver")) and len(result["exfiltration_channels"]) < 10:
                result["exfiltration_channels"].append({
                    "channel": "c2_drop_endpoint",
                    "destination": req.url[:300],
                    "method": req.method
                })

        page.on("request", on_request)

        # Track navigation redirect chain
        redirect_chain = [TARGET_URL]

        def on_response(res):
            if res.status in (301, 302, 303, 307, 308):
                loc = res.headers.get("location")
                if loc:
                    redirect_chain.append(loc)
                    result["redirect_chain_detail"].append({"from": res.url[:300], "status": res.status, "to": loc[:300]})

        page.on("response", on_response)

        # Client-side navigations (window.location swaps, meta refresh) on the top frame.
        def on_nav(frame):
            if frame == page.main_frame and frame.url and frame.url not in redirect_chain:
                result["js_navigations"].append(frame.url[:300])
                redirect_chain.append(frame.url)

        page.on("framenavigated", on_nav)

        # Navigate with hard timeout (20s)
        try:
            resp = page.goto(nav_url, wait_until="load", timeout=NAV_TIMEOUT_MS)
            if resp and resp.status >= 400:
                result["http_status"] = resp.status
        except PlaywrightTimeoutError:
            result["error"] = f"Navigation timed out ({NAV_TIMEOUT_MS // 1000}s limit reached)"
        except Exception as ex:
            err_str = str(ex)
            if "CERT" in err_str.upper() or "SSL" in err_str.upper():
                result["tls_error"] = True
            result["error"] = f"Navigation error: {err_str}"

        # Wait briefly for dynamic JS and client-side rendering
        page.wait_for_timeout(SETTLE_MS)

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

        # Extract DOM data and save raw DOM snapshot for forensics
        try:
            dom_path = os.path.join(OUT_DIR, "dom_snapshot.html")
            with open(dom_path, "w", encoding="utf-8") as f:
                f.write(page.content())
        except Exception:
            pass

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
                const otpRe = /(^|[^a-z])(otp|2fa|mfa|passcode|one[-_ ]?time|verification[-_ ]?code|security[-_ ]?code|pin)([^a-z]|$)/i;
                const cardRe = /(^|[^a-z])(card[-_ ]?(number|no|num)?|cc[-_ ]?(num|number)|cvv|cvc|expir(y|ation)|debit|credit[-_ ]?card)([^a-z]|$)/i;
                const formInfo = forms.slice(0, 15).map(f => {
                    const ins = Array.from(f.querySelectorAll('input, select, textarea'));
                    const label = i => [i.name, i.id, i.placeholder, i.autocomplete].join(' ');
                    return {
                        action: f.action || location.href,
                        method: (f.method || 'get').toLowerCase(),
                        input_count: ins.length,
                        has_password: ins.some(i => (i.type || '').toLowerCase() === 'password'),
                        has_otp: ins.some(i => ['text','tel','number','password'].includes((i.type || 'text').toLowerCase()) && otpRe.test(label(i))),
                        has_card: ins.some(i => ['text','tel','number'].includes((i.type || 'text').toLowerCase()) && cardRe.test(label(i))),
                    };
                });
                const iframes = Array.from(document.querySelectorAll('iframe')).slice(0, 15).map(fr => {
                    let cross = false, host = '';
                    try { const u = new URL(fr.src, location.href); host = u.hostname; cross = u.hostname !== location.hostname; } catch (e) {}
                    const r = fr.getBoundingClientRect();
                    return { src: (fr.src || '').slice(0, 300), host, cross_origin: cross, visible: r.width > 20 && r.height > 20 };
                });
                const mutations = window.__pc_mutations || [];
                
                const allInputs = Array.from(document.querySelectorAll('input, select, textarea'));
                const inputs = allInputs.map(i => ({
                    type: (i.type || 'text').toLowerCase(),
                    name: i.name || '',
                    id: i.id || '',
                    placeholder: i.placeholder || '',
                    autocomplete: i.autocomplete || ''
                }));

                return { actions, inputs, formInfo, iframes, mutations };
            }""")

            result["form_actions"] = extracted_forms.get("actions", [])
            result["forms"] = extracted_forms.get("formInfo", [])
            result["iframes"] = extracted_forms.get("iframes", [])
            result["dom_mutations"] = extracted_forms.get("mutations", [])
            inputs_list = extracted_forms.get("inputs", [])
            result["fields"]["inputs"] = inputs_list

            password_count = sum(1 for i in inputs_list if i["type"] == "password")
            
            # Whole-token matching on text-like inputs only: substrings such as "expand", "discard",
            # "zipcode", "spinner" or "searchToken" must never count as OTP / card fields.
            otp_pattern = re.compile(r"(^|[^a-z])(otp|2fa|mfa|passcode|one[-_ ]?time|verification[-_ ]?code|security[-_ ]?code|pin)([^a-z]|$)", re.IGNORECASE)
            card_pattern = re.compile(r"(^|[^a-z])(card[-_ ]?(number|no|num)?|cc[-_ ]?(num|number)|cvv|cvc|expir(y|ation)|debit|credit[-_ ]?card)([^a-z]|$)", re.IGNORECASE)
            text_like = ("text", "tel", "number", "password")

            otp_count = sum(1 for i in inputs_list if i.get("type") in text_like and (
                otp_pattern.search(i.get("name", "")) or
                otp_pattern.search(i.get("placeholder", "")) or
                otp_pattern.search(i.get("id", ""))
            ))

            card_count = sum(1 for i in inputs_list if i.get("type") in ("text", "tel", "number") and (
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
