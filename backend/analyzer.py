"""
analyzer.py - Two-tier agentic evaluation engine for Phish&Chips.

Tier 1 (deterministic, no model): reputation gate + physical-signal heuristics.
    A verified reputable apex that landed on itself, with no physically-observed anomaly,
    is benign immediately. The model is never consulted, so it cannot hallucinate a
    verdict about Wikipedia.
Tier 2 (reasoning model): ambiguous / suspicious / unknown / user-content targets receive a
    rich evidence document (DOM summary, forms, network origins, redirect chain, screenshot)
    and must answer in the enforced ModelVerdict schema.

Failure policy: timeout, API error, rate-limit or schema drift NEVER yields "malicious".
The job degrades to "indeterminate" (Analysis Incomplete - Retry / Manual Review), or at
most "suspicious" when hard physical evidence exists.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from dotenv import load_dotenv

import metrics
from domain_checks import corroborate_apex
from heuristics import evaluate_heuristics
from reputation import apex_domain, classify_reputation, extract_host, is_reputable, is_user_content_host, same_site
from schemas import (
    LEGACY_VERDICT,
    MODEL_OUTPUT_SCHEMA_TEXT,
    ModelVerdict,
    SchemaViolation,
    parse_model_output,
)

load_dotenv()

TOTAL_BUDGET_SECONDS = float(os.getenv("TOTAL_BUDGET_SECONDS", "20"))
MIN_INFERENCE_SECONDS = float(os.getenv("MIN_INFERENCE_SECONDS", "3"))

LLMCall = Callable[[List[Dict[str, Any]], float], Awaitable[str]]


class InferenceUnavailable(Exception):
    """Transport/API failure. `reason` is a metrics label (timeout|rate_limit|api_error)."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


# --------------------------------------------------------------------------- config / transport

def get_vultr_config() -> Dict[str, str]:
    api_key = os.getenv("VULTR_INFERENCE_API_KEY") or os.getenv("VULTR_API_KEY", "")
    return {
        "api_key": api_key.strip(),
        "base_url": os.getenv("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1").strip(),
        "model": os.getenv("VULTR_MODEL", "llama2-13b-chat").strip(),
    }


def encode_image_base64(image_path: Path) -> Optional[str]:
    try:
        if image_path.exists() and image_path.stat().st_size > 0:
            return "data:image/png;base64," + base64.b64encode(image_path.read_bytes()).decode("utf-8")
    except OSError as e:
        print(f"Error encoding image {image_path}: {e}")
    return None


def is_vision_model(model_name: str) -> bool:
    """True if model accepts image_url inputs. Pure text models (qwen, deepseek, llama) return empty on images."""
    name = (model_name or "").lower()
    return any(v in name for v in ("vision", "vl", "omni", "multimodal", "gpt-4o", "gemini-1.5", "gemini-2.0", "claude-3"))


def _sync_chat(messages: List[Dict[str, Any]], timeout: float, config: Dict[str, str]) -> str:
    import openai

    client = openai.OpenAI(base_url=config["base_url"], api_key=config["api_key"], timeout=timeout, max_retries=0)
    kwargs = dict(model=config["model"], messages=messages, temperature=0.0, max_tokens=1500)
    try:
        try:
            resp = client.chat.completions.create(response_format={"type": "json_object"}, **kwargs)
        except openai.BadRequestError as e:
            # Only a 400 means "feature unsupported" - retry once without response_format.
            if "image" in str(e).lower():
                raise
            resp = client.chat.completions.create(**kwargs)
    except openai.APITimeoutError as e:
        raise InferenceUnavailable("timeout", str(e)) from e
    except openai.RateLimitError as e:
        raise InferenceUnavailable("rate_limit", str(e)) from e
    except openai.BadRequestError as e:
        raise InferenceUnavailable("bad_request", str(e)) from e
    except (openai.APIConnectionError, openai.APIStatusError) as e:
        raise InferenceUnavailable("api_error", str(e)) from e
    content = resp.choices[0].message.content if resp.choices and resp.choices[0].message else None
    if not content or not content.strip():
        raise InferenceUnavailable("empty_response", "model returned empty content")
    return content


def _default_llm_call_factory(config: Dict[str, str]) -> LLMCall:
    async def _call(messages: List[Dict[str, Any]], timeout: float) -> str:
        return await asyncio.to_thread(_sync_chat, messages, timeout, config)

    return _call


# --------------------------------------------------------------------------- evidence + prompt

_SYSTEM_PROMPT = (
    "You are the Tier-2 reasoning analyst of a phishing detonation sandbox. You receive a JSON evidence "
    "document of what a real headless browser OBSERVED. Judge behaviour, not vocabulary.\n"
    "RULES:\n"
    "1. Never classify on URL length, query strings, edit/action tokens, or brand words alone.\n"
    "2. `reputation.tier1_status` = 'reputable-apex' means the apex belongs to a verified top-tier domain. "
    "A reputable site is NOT an impersonation target of itself. Only flag it for sub-path anomalies: an "
    "off-site open redirect, defacement, credential form posting to another registrable domain, or injected login UI.\n"
    "3. 'user-content-host' means anyone can host pages there: inspect the page itself, do not trust the apex.\n"
    "4. 'malicious' REQUIRES at least one physically observed indicator: credential fields whose form posts to a "
    "different registrable domain, brand impersonation on an unofficial domain WITH credential capture, covert download, "
    "off-apex redirect from a trusted origin, or injected login overlay. Otherwise choose 'suspicious' or 'benign'.\n"
    "5. Cross-verify before answering. Each evidence_chain entry must be '<claim> -> <observation>', e.g. "
    "'Claims to be Wikipedia -> landing apex wikipedia.org is reputable and TLS org is Wikimedia Foundation', "
    "'Credential theft possible? -> no password/OTP/card fields and no cross-origin form action'.\n"
    "6. Heuristic signals provided are hints; hard_signals are physically observed, soft_signals are weak.\n"
    "Reply with ONLY one JSON object, no prose, no markdown, exactly this schema:\n" + MODEL_OUTPUT_SCHEMA_TEXT
)


def _origins_by_apex(domains: List[str]) -> List[str]:
    return sorted({apex_domain(d) for d in domains if d})[:25]


def build_evidence(result_data: Dict[str, Any], heuristics: Dict[str, Any], tier1_status: str) -> Dict[str, Any]:
    final_url = result_data.get("final_url") or ""
    requested = result_data.get("url") or final_url
    fields = result_data.get("fields", {}) or {}
    forms = result_data.get("forms") or [{"action": a} for a in result_data.get("form_actions", [])]
    return {
        "requested_url": requested,
        "final_url": final_url,
        "reputation": {
            "tier1_status": tier1_status,
            "requested_apex": apex_domain(requested),
            "landing_apex": apex_domain(final_url),
            "same_site": same_site(requested, final_url),
            "domain_intel": result_data.get("domain_intel"),
        },
        "navigation": {
            "redirect_chain": result_data.get("redirect_chain_detail") or result_data.get("redirect_chain", []),
            "js_navigations": result_data.get("js_navigations", []),
        },
        "page": {
            "title": result_data.get("title", ""),
            "dom_text_summary": (result_data.get("text") or "")[:1800],
            "has_logo_or_icon": result_data.get("has_logo_or_icon"),
        },
        "forms": forms[:10],
        "sensitive_field_counts": {
            "password": fields.get("password", 0),
            "otp_like": fields.get("otp_like", 0),
            "card_like": fields.get("card_like", 0),
        },
        "network": {
            "external_origins": _origins_by_apex(result_data.get("external_domains", [])),
            "external_post_requests": result_data.get("post_requests", [])[:10],
        },
        "iframes": result_data.get("iframes", [])[:10],
        "dom_mutations": result_data.get("dom_mutations", [])[:10],
        "blocked_events": result_data.get("blocked_events", [])[:10],
        "reverse_engineering": {
            "has_disassembly": (result_data.get("re_intelligence") or {}).get("has_disassembly", False),
            "attribution_summary": (result_data.get("re_intelligence") or {}).get("attribution_summary", "None"),
            "mitre_tactics": (result_data.get("re_intelligence") or {}).get("mitre_tactics", []),
            "artifacts": [
                {
                    "name": a.get("name"),
                    "type": a.get("type"),
                    "entropy": a.get("entropy"),
                    "is_packed": a.get("is_packed"),
                    "suspicious_apis": a.get("suspicious_apis", [])[:5],
                    "capabilities": a.get("capabilities", [])[:5],
                }
                for a in (result_data.get("re_intelligence") or {}).get("artifacts", [])[:5]
            ]
        },
        "heuristic_signals": {
            "hard": [s["indicator"] for s in heuristics.get("hard_signals", [])],
            "soft": [s["indicator"] for s in heuristics.get("soft_signals", [])],
        },
    }


def _write_payload_log(job_dir: Path, evidence: Dict[str, Any], image_b64: Optional[str], model: str) -> Dict[str, Any]:
    """Persist the exact (text) payload for audit; images are logged as hash+size, not inlined."""
    summary = {
        "model": model,
        "evidence_keys": sorted(evidence.keys()),
        "has_screenshot": bool(image_b64),
        "screenshot_sha256": hashlib.sha256(image_b64.encode()).hexdigest()[:16] if image_b64 else None,
        "screenshot_bytes_b64": len(image_b64) if image_b64 else 0,
    }
    try:
        (job_dir / "inference_payload.json").write_text(
            json.dumps({"summary": summary, "evidence": evidence}, indent=2, default=str), encoding="utf-8"
        )
    except OSError:
        pass
    metrics.log_json("inference_payload", **summary, url=evidence.get("final_url"))
    return summary


# --------------------------------------------------------------------------- reconciliation

def _threat_type(verdict: str, heuristics: Dict[str, Any], llm: Optional[ModelVerdict]) -> str:
    if verdict == "benign":
        return "none"
    codes = {s["code"] for s in heuristics.get("hard_signals", [])}
    if codes & {"cross_origin_credential_form", "credential_exfil_request", "brand_mismatch_credentials", "injected_login_ui"}:
        return "credential_harvest"
    if codes & {"auto_download", "wasm_evasion_module", "packed_binary_payload"}:
        return "malware_delivery"
    if "off_apex_redirect" in codes:
        return "open_redirect"
    text = " ".join((llm.indicators + llm.evidence_chain) if llm else []).lower()
    if "scareware" in text or "virus" in text or "support scam" in text:
        return "scareware"
    return "suspicious_behavior"


def _package(
    verdict: str,
    confidence: float,
    *,
    tier: str,
    engine: str,
    indicators: List[str],
    evidence_chain: List[str],
    heuristics: Dict[str, Any],
    llm: Optional[ModelVerdict] = None,
    analysis_complete: bool = True,
    degraded_reason: Optional[str] = None,
    threat_source: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    reasons = [e.split("->")[-1].strip() if "->" in e else e for e in evidence_chain][:3]
    out = {
        "verdict": LEGACY_VERDICT[verdict],
        "verdict_class": verdict,
        "confidence": round(float(confidence), 2),
        "indicators": indicators,
        "evidence_chain": evidence_chain,
        "reasons": reasons or indicators[:3],
        "pretending_to_be": (llm.pretending_to_be if llm and llm.pretending_to_be else heuristics.get("pretending_to_be")),
        "asks_for": list(dict.fromkeys(heuristics.get("asks_for", []) + (llm.asks_for if llm else []))),
        "threat_type": _threat_type(verdict, heuristics, llm),
        "tier": tier,
        "engine": engine,
        "analysis_complete": analysis_complete,
        "degraded_reason": degraded_reason,
        "threat_source": threat_source,
        "needs_manual_review": verdict in ("indeterminate", "suspicious"),
    }
    if extra:
        out.update(extra)
    return out


def reconcile(llm: ModelVerdict, heuristics: Dict[str, Any], tier1_status: str) -> tuple:
    """Merge model verdict with physical heuristic evidence. Returns (verdict, confidence, notes)."""
    hard = heuristics.get("hard_signals", [])
    heur_scam = heuristics.get("heuristic_verdict") == "SCAM"
    notes: List[str] = []
    verdict, conf = llm.verdict, llm.confidence

    if verdict == "malicious" and not hard:
        # A model alone can never convict: malicious requires physically observed hard evidence.
        verdict, conf = "suspicious", min(conf, 0.7)
        notes.append("Model claimed malicious without physically observed corroboration -> downgraded to suspicious for manual review")
    elif verdict == "benign" and hard:
        verdict, conf = "suspicious", min(conf, 0.7)
        notes.append("Model judged benign but sandbox physically observed anomalies -> escalated to suspicious for review")
    elif verdict == "suspicious" and heur_scam and hard:
        verdict, conf = "malicious", max(conf, 0.85)
        notes.append("Model suspicion corroborated by hard physical evidence -> malicious")
    elif verdict == "benign" and tier1_status == "reputable-apex":
        conf = max(conf, 0.9)
    return verdict, conf, notes


# --------------------------------------------------------------------------- main pipeline

async def analyze_threat(
    result_data: Dict[str, Any],
    job_dir: Path,
    deadline: Optional[float] = None,
    llm_call: Optional[LLMCall] = None,
) -> Dict[str, Any]:
    """
    deadline: absolute time.monotonic() value by which the whole job must finish.
    llm_call: injectable transport (used by tests); defaults to Vultr Serverless Inference.
    """
    if deadline is None:
        deadline = time.monotonic() + TOTAL_BUDGET_SECONDS
    config = get_vultr_config()
    final_url = result_data.get("final_url") or result_data.get("url") or ""
    requested_url = result_data.get("url") or final_url

    # Sandbox-level failure with nothing observed -> never guess.
    if result_data.get("error") and not (result_data.get("title") or result_data.get("text")):
        metrics.FAST_PATH_TOTAL.labels("sandbox_no_artifacts").inc()
        return _package(
            "indeterminate", 0.0, tier="none", engine="sandbox", indicators=["Sandbox produced no page artifacts"],
            evidence_chain=[f"Page analysable? -> no: {str(result_data.get('error'))[:160]}"],
            heuristics={}, analysis_complete=False, degraded_reason="sandbox_no_artifacts",
            threat_source="Analysis Incomplete (Retry)",
        )

    # --- Tier 1a: reputation + DNS/TLS/RDAP corroboration (bounded) -------------------------
    landing_reputation = classify_reputation(final_url)
    origin_reputation = classify_reputation(requested_url)
    if is_user_content_host(final_url) or is_user_content_host(requested_url):
        tier1_status = "user-content-host"
    elif landing_reputation == "reputable":
        tier1_status = "reputable-apex"
    else:
        tier1_status = "unverified"

    if tier1_status != "reputable-apex":
        remaining = max(0.0, deadline - time.monotonic() - MIN_INFERENCE_SECONDS)
        if remaining > 0.5:
            result_data["domain_intel"] = await corroborate_apex(final_url, budget=min(2.5, remaining))

    heuristics = evaluate_heuristics(result_data)
    hard = heuristics["hard_signals"]

    # --- Tier 1b: fast-pass for verified reputable apex with no physical anomaly ------------
    landed_on_itself = same_site(requested_url, final_url) and origin_reputation == "reputable"
    if tier1_status == "reputable-apex" and landed_on_itself and not hard:
        metrics.FAST_PATH_TOTAL.labels("benign_fast_pass").inc()
        chain = [
            f"Claims to be {apex_domain(final_url)} -> landing apex is a verified top-tier domain (reputation list) "
            "and the sandbox landed on the requested apex",
            "Open redirect / hijack? -> no off-apex redirect observed",
            "Credential exfiltration? -> no credential form posting to another registrable domain; no injected login UI",
        ]
        return _package(
            "benign", 0.97, tier="tier1", engine="reputation-gate+sandbox",
            indicators=[], evidence_chain=chain, heuristics=heuristics,
            threat_source="Tier 1: Reputation Gate + Sandbox Behavioural Checks",
        )
    if tier1_status == "reputable-apex":
        metrics.FAST_PATH_TOTAL.labels("reputable_anomaly_escalated").inc()
    else:
        metrics.FAST_PATH_TOTAL.labels(f"not_eligible_{tier1_status}").inc()

    # --- Tier 2: reasoning model ------------------------------------------------------------
    if llm_call is None and not config["api_key"]:
        return _heuristics_only(heuristics, tier1_status)

    call = llm_call or _default_llm_call_factory(config)
    evidence = build_evidence(result_data, heuristics, tier1_status)
    image_b64 = encode_image_base64(job_dir / "shot1.png")
    _write_payload_log(job_dir, evidence, image_b64, config["model"])

    user_text = "SANDBOX EVIDENCE (JSON):\n" + json.dumps(evidence, default=str)
    messages_text = [{"role": "system", "content": _SYSTEM_PROMPT}, {"role": "user", "content": user_text}]
    messages_vision = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": [{"type": "text", "text": user_text}, {"type": "image_url", "image_url": {"url": image_b64}}]},
    ] if (image_b64 and is_vision_model(config["model"])) else None

    attempts = [m for m in (messages_vision, messages_text) if m]
    last_reason = "no_attempt"
    for idx, messages in enumerate(attempts):
        remaining = deadline - time.monotonic()
        if remaining < MIN_INFERENCE_SECONDS:
            last_reason = "budget"
            metrics.BUDGET_EXCEEDED.inc()
            break
        t0 = time.monotonic()
        try:
            raw = await asyncio.wait_for(call(messages, remaining), timeout=remaining)
            metrics.INFERENCE_LATENCY.observe(time.monotonic() - t0)
            llm = parse_model_output(raw)
        except asyncio.TimeoutError:
            last_reason = "timeout"
            metrics.INFERENCE_FAILURES.labels("timeout").inc()
            break
        except InferenceUnavailable as e:
            last_reason = e.reason
            metrics.INFERENCE_FAILURES.labels(e.reason).inc()
            if e.reason in ("bad_request", "empty_response") and idx == 0 and len(attempts) > 1:
                continue  # model likely not multimodal or rejected vision payload: fall back to text-only evidence
            break
        except SchemaViolation as e:
            last_reason = "schema_violation"
            metrics.SCHEMA_VIOLATIONS.inc()
            metrics.INFERENCE_FAILURES.labels("schema_violation").inc()
            metrics.log_json("schema_violation", detail=str(e)[:200], url=final_url)
            if idx == 0 and len(attempts) > 1:
                continue  # retry with text-only payload if first attempt was vision
            continue  # one retry with next payload shape if time remains
        verdict, conf, notes = reconcile(llm, heuristics, tier1_status)
        chain = llm.evidence_chain + notes
        indicators = list(dict.fromkeys(llm.indicators + heuristics["indicators"]))[:12]
        return _package(
            verdict, conf, tier="tier2", engine="vision" if messages is messages_vision else "text",
            indicators=indicators, evidence_chain=chain, heuristics=heuristics, llm=llm,
            threat_source=f"Tier 2: Vultr Serverless Inference ({config['model']}) + Sandbox Evidence",
            extra={"model_verdict": llm.verdict, "payload": "see inference_payload.json"},
        )

    return _degraded(heuristics, last_reason)


def _heuristics_only(heuristics: Dict[str, Any], tier1_status: str) -> Dict[str, Any]:
    """Inference deliberately unconfigured (not a failure): deterministic physical-evidence verdict."""
    hv = heuristics["heuristic_verdict"]
    hard = heuristics["hard_signals"]
    if hv == "SCAM" and hard:
        verdict, conf = "malicious", min(0.95, heuristics["heuristic_score"] / 100.0)
    elif hv == "SUSPICIOUS":
        verdict, conf = "suspicious", 0.6
    else:
        verdict, conf = "benign", 0.6
    chain = [f"{s['indicator']} -> physically observed in sandbox" for s in hard] or [
        "Physical evidence of credential theft, covert download or off-site redirect? -> none observed"
    ]
    return _package(
        verdict, conf, tier="tier1", engine="heuristics-only", indicators=heuristics["indicators"],
        evidence_chain=chain, heuristics=heuristics, threat_source="Deterministic Sandbox Heuristics (inference not configured)",
    )


def _degraded(heuristics: Dict[str, Any], reason: str) -> Dict[str, Any]:
    """Inference failed/timed out/drifted. NEVER malicious; manual review instead."""
    hard = heuristics.get("hard_signals", [])
    verdict = "suspicious" if hard else "indeterminate"
    chain = [f"Model verdict available? -> no ({reason}); Analysis Incomplete (Retry)"] + [
        f"{s['indicator']} -> physically observed in sandbox" for s in hard
    ]
    return _package(
        verdict, 0.0 if not hard else 0.5, tier="tier2", engine="degraded", indicators=heuristics.get("indicators", []),
        evidence_chain=chain, heuristics=heuristics, analysis_complete=False, degraded_reason=reason,
        threat_source="Analysis Incomplete (Retry) - Manual Review",
    )
