import json
import time
from pathlib import Path

import pytest

import analyzer
import reputation
from heuristics import evaluate_heuristics
from schemas import SchemaViolation, parse_model_output

pytestmark = pytest.mark.asyncio


# ----------------------------------------------------------------------------- helpers

def telemetry(url, final, title="", text="", chain=None, **extra):
    t = {
        "url": url, "final_url": final, "redirect_chain": chain or [url, final], "title": title, "text": text,
        "fields": {"password": 0, "otp_like": 0, "card_like": 0, "inputs": []},
        "form_actions": [], "forms": [], "external_domains": [], "blocked_events": [], "error": None,
    }
    t.update(extra)
    return t


def cred_form(t, action):
    t["fields"]["password"] = 1
    t["fields"]["inputs"] = [{"type": "password", "name": "p"}]
    t["form_actions"] = [action]
    t["forms"] = [{"action": action, "method": "post", "has_password": True, "has_otp": False, "has_card": False}]
    return t


class Recorder:
    def __init__(self, reply):
        self.reply, self.calls = reply, 0

    async def __call__(self, messages, timeout):
        self.calls += 1
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply(messages) if callable(self.reply) else self.reply


def verdict_json(v, conf=0.9, indicators=("x",), chain=("claim -> obs",)):
    return json.dumps({"verdict": v, "confidence": conf, "indicators": list(indicators), "evidence_chain": list(chain)})


def run(t, llm=None, tmp=Path("/tmp"), seconds=20):
    return analyzer.analyze_threat(t, tmp, deadline=time.monotonic() + seconds, llm_call=llm)


WIKI = telemetry(
    "https://wikipedia.org", "https://www.wikipedia.org/", "Wikipedia",
    "Wikipedia The Free Encyclopedia. Download on the App Store apple microsoft sbi amazon. Donate 5 10 20",
    form_actions=["https://donate.wikimedia.org/w/index.php"],
    forms=[{"action": "https://donate.wikimedia.org/w/index.php", "method": "get", "has_password": False, "has_otp": False, "has_card": False}],
    external_domains=["upload.wikimedia.org"],
)


# ----------------------------------------------------------------------------- reputation

async def test_reputation_gate_basics():
    assert reputation.is_reputable("https://www.wikipedia.org/")
    assert reputation.is_reputable("github.com")
    assert reputation.reputation_list_size() >= 5000
    assert reputation.apex_domain("https://en.m.wikipedia.org/wiki/X") == "wikipedia.org"
    assert reputation.apex_domain("https://www.example.co.uk/") == "example.co.uk"


@pytest.mark.parametrize("url", [
    "https://evil.github.io/login", "https://storage.googleapis.com/b/index.html", "https://sites.google.com/view/x",
    "https://foo.blogspot.com/", "https://x.web.app/", "https://bucket.s3.amazonaws.com/a.html",
])
async def test_user_content_hosts_never_reputable(url):
    assert not reputation.is_reputable(url)


async def test_lookalike_not_reputable():
    assert not reputation.is_reputable("https://wikipedia.org.evil.xyz/")
    assert not reputation.is_reputable("https://wikipedia-login.com/")
    assert reputation.is_reputable("https://www.nasa.gov/") and reputation.is_reputable("https://cs.mit.edu/")


# ----------------------------------------------------------------------------- schema

async def test_schema_accepts_valid_and_fenced():
    v = parse_model_output("```json\n" + verdict_json("Benign") + "\n```")
    assert v.verdict == "benign" and v.confidence == 0.9


@pytest.mark.parametrize("raw", [
    "", "The site looks safe.", "[]", '{"verdict":"safe","confidence":.9,"evidence_chain":["a"]}',
    '{"verdict":"scam","confidence":.9,"indicators":["a"],"evidence_chain":["a"]}',
    '{"verdict":"benign","confidence":1.4,"evidence_chain":["a"]}',
    '{"verdict":"benign","confidence":0.9}',
    '{"verdict":"malicious","confidence":0.9,"evidence_chain":["a"]}',
    '{"verdict":"benign","confidence":0.9,"evidence_chain":["a"],"extra":1}',
])
async def test_schema_rejects_drift(raw):
    with pytest.raises(SchemaViolation):
        parse_model_output(raw)


# ----------------------------------------------------------------------------- heuristics (root cause)

async def test_wikipedia_text_not_flagged_by_lexical_heuristics():
    h = evaluate_heuristics(json.loads(json.dumps(WIKI)))
    assert h["heuristic_verdict"] == "SAFE" and not h["hard_signals"]


async def test_brand_substring_does_not_match():
    t = telemetry("https://example.org/", "https://example.org/", "Pineapple recipes", "Our pineapple dessert. Visit possibly apples.")
    assert evaluate_heuristics(t)["pretending_to_be"] is None


async def test_soft_signals_alone_never_scam():
    t = telemetry("https://a.xyz/", "https://xn--b.xyz/?x=" + "a" * 500 + "&action=edit", chain=["https://a.xyz/", "https://b.top/", "https://xn--b.xyz/"])
    t["fields"]["password"] = 1
    h = evaluate_heuristics(t)
    assert h["heuristic_verdict"] in ("SAFE", "SUSPICIOUS") and not h["hard_signals"]


async def test_fake_bank_is_scam_via_hard_evidence():
    t = cred_form(telemetry("https://sbi-kyc.xyz/", "https://sbi-kyc.xyz/", "SBI Online Banking", "SBI login"), "https://sbi-kyc.xyz/p.php")
    h = evaluate_heuristics(t)
    assert h["heuristic_verdict"] == "SCAM" and h["pretending_to_be"] == "State Bank of India"


# ----------------------------------------------------------------------------- analyzer / pipeline

async def test_wikipedia_fast_pass_never_calls_model(tmp_path):
    llm = Recorder(verdict_json("malicious", 0.98))
    res = await run(json.loads(json.dumps(WIKI)), llm, tmp_path)
    assert res["verdict_class"] == "benign" and res["tier"] == "tier1" and llm.calls == 0
    assert res["verdict"] == "SAFE" and res["evidence_chain"]


async def test_reputable_login_page_same_site_is_benign(tmp_path):
    t = cred_form(telemetry("https://github.com/login", "https://github.com/login", "Sign in to GitHub"), "https://github.com/session")
    res = await run(t, Recorder(verdict_json("malicious")), tmp_path)
    assert res["verdict_class"] == "benign"


async def test_open_redirect_from_reputable_origin_escalates(tmp_path):
    start = "https://google.com/url?q=https://evil-login.xyz/"
    t = cred_form(telemetry(start, "https://evil-login.xyz/", "Sign in", "Enter password"), "https://evil-login.xyz/p.php")
    llm = Recorder(lambda m: verdict_json("malicious", 0.95, ("open redirect",), ("trusted origin -> off-apex landing",)))
    res = await run(t, llm, tmp_path)
    assert llm.calls == 1 and res["verdict_class"] == "malicious" and res["threat_type"] == "open_redirect"


async def test_user_content_host_gets_full_inspection(tmp_path):
    t = cred_form(telemetry("https://x.github.io/", "https://x.github.io/", "Paytm KYC", "paytm kyc update"), "https://collector.top/c")
    llm = Recorder(verdict_json("malicious", 0.9))
    res = await run(t, llm, tmp_path)
    assert llm.calls == 1 and res["verdict_class"] == "malicious"


async def test_timeout_is_indeterminate_not_malicious(tmp_path):
    async def slow(messages, timeout):
        import asyncio
        await asyncio.sleep(5)

    analyzer.MIN_INFERENCE_SECONDS = 0.1
    t = telemetry("https://unknown-site.io/", "https://unknown-site.io/", "Hello", "hi")
    res = await analyzer.analyze_threat(t, tmp_path, deadline=time.monotonic() + 0.6, llm_call=slow)
    assert res["verdict_class"] == "indeterminate" and res["degraded_reason"] == "timeout" and res["analysis_complete"] is False
    assert res["verdict"] == "INDETERMINATE"
    analyzer.MIN_INFERENCE_SECONDS = 3.0


@pytest.mark.parametrize("reply", [
    "I think it's phishing!", '{"verdict":"scam","confidence":0.9,"indicators":["a"],"evidence_chain":["a"]}',
    analyzer.InferenceUnavailable("rate_limit"), analyzer.InferenceUnavailable("api_error"),
])
async def test_failures_never_default_to_malicious(tmp_path, reply):
    t = telemetry("https://unknown-site.io/", "https://unknown-site.io/", "Order status", "tracking " + "x" * 50)
    t["forms"] = [{"action": "https://unknown-site.io/q", "has_password": False}]
    res = await run(t, Recorder(reply), tmp_path)
    assert res["verdict_class"] == "indeterminate" and res["needs_manual_review"] and res["analysis_complete"] is False


async def test_failure_with_hard_evidence_caps_at_suspicious(tmp_path):
    t = cred_form(telemetry("https://sbi-kyc.xyz/", "https://sbi-kyc.xyz/", "SBI Online Banking", "SBI login"), "https://sbi-kyc.xyz/p.php")
    res = await run(t, Recorder(analyzer.InferenceUnavailable("timeout")), tmp_path)
    assert res["verdict_class"] == "suspicious"


async def test_malicious_without_corroboration_downgraded(tmp_path):
    t = telemetry("https://quiet-shop.com/", "https://quiet-shop.com/", "Quiet Shop", "Welcome to our shop")
    res = await run(t, Recorder(verdict_json("malicious", 0.99)), tmp_path)
    assert res["verdict_class"] == "suspicious" and res["confidence"] <= 0.7


async def test_model_benign_overridden_by_physical_exfiltration(tmp_path):
    t = cred_form(telemetry("https://portal-x.com/", "https://portal-x.com/", "Portal", "Login"), "https://collector.top/c")
    res = await run(t, Recorder(verdict_json("benign", 0.9)), tmp_path)
    assert res["verdict_class"] == "suspicious"


async def test_sandbox_failure_without_artifacts_is_indeterminate(tmp_path):
    t = telemetry("https://x.com/", "https://x.com/", error="Navigation error: net::ERR")
    res = await run(t, None, tmp_path)
    assert res["verdict_class"] == "indeterminate"


async def test_inference_payload_is_rich_and_logged(tmp_path, monkeypatch):
    monkeypatch.setenv("VULTR_MODEL", "qwen-vl-max")
    (tmp_path / "shot1.png").write_bytes(b"\x89PNG fake")
    t = cred_form(telemetry("https://unknown.io/", "https://unknown.io/", "Title Z", "Body text Z"), "https://unknown.io/s")
    t["external_domains"] = ["cdn.other.com"]
    seen = {}

    async def spy(messages, timeout):
        seen["messages"] = messages
        return verdict_json("benign")

    await run(t, spy, tmp_path)
    payload = json.loads((tmp_path / "inference_payload.json").read_text())
    ev = payload["evidence"]
    assert {"page", "forms", "network", "navigation", "reputation", "iframes", "dom_mutations"} <= set(ev)
    assert ev["page"]["title"] == "Title Z" and "other.com" in ev["network"]["external_origins"]
    assert payload["summary"]["has_screenshot"] is True
    user = seen["messages"][-1]["content"]
    assert isinstance(user, list) and user[1]["type"] == "image_url"  # screenshot attached to the vision call


async def test_no_key_demo_bank_is_malicious_via_heuristics(tmp_path):
    t = cred_form(telemetry("demo://fake-bank", "file:///app/demo/bank_login.html", "SBI Online Banking", "State Bank of India login"), "https://evil.example.top/post")
    res = await run(t, None, tmp_path)
    assert res["engine"] in ("heuristics-only",) and res["verdict_class"] in ("suspicious", "malicious")


async def test_sync_chat_reasoning_fallback(monkeypatch):
    class FakeMessage:
        content = ""
        reasoning = 'Thinking...\nBased on the evidence:\n{"verdict": "benign", "confidence": 0.85, "indicators": ["genuine"], "evidence_chain": ["c1"]}'

    class FakeChoice:
        message = FakeMessage()

    class FakeResponse:
        choices = [FakeChoice()]

    class FakeCompletions:
        def create(self, **kwargs):
            return FakeResponse()

    class FakeChat:
        completions = FakeCompletions()

    class FakeClient:
        chat = FakeChat()

    monkeypatch.setattr("openai.OpenAI", lambda **kwargs: FakeClient())
    config = {"base_url": "https://api.vultr.com/v1", "api_key": "fake", "model": "glm-5.3"}
    res = analyzer._sync_chat([{"role": "user", "content": "hi"}], 10.0, config)
    parsed = json.loads(res)
    assert parsed["verdict"] == "benign"
    assert parsed["confidence"] == 0.85

