"""
analyzer.py - Vultr Serverless Inference Threat Engine for Phish&Chips.
Calls vision/text models via OpenAI-compatible SDK with robust fallback to deterministic heuristics.
"""

import os
import json
import base64
from pathlib import Path
from typing import Dict, Any, List, Optional
from openai import OpenAI
from dotenv import load_dotenv

from heuristics import evaluate_heuristics

load_dotenv()

def get_vultr_config():
    return {
        "api_key": os.getenv("VULTR_INFERENCE_API_KEY", "").strip(),
        "base_url": os.getenv("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1").strip(),
        "model": os.getenv("VULTR_MODEL", "llama2-13b-chat").strip()
    }

def encode_image_base64(image_path: Path) -> Optional[str]:
    """Encodes an image file to a base64 data URI."""
    try:
        if image_path.exists() and image_path.stat().st_size > 0:
            with open(image_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("utf-8")
                return f"data:image/png;base64,{b64}"
    except Exception as e:
        print(f"Error encoding image {image_path}: {e}")
    return None

def clean_json_markdown(raw_content: str) -> str:
    """Strips markdown code fences and whitespace from model output."""
    text = raw_content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text

def parse_model_json(raw_content: str) -> Optional[Dict[str, Any]]:
    """Attempts to safely parse JSON from raw LLM output."""
    cleaned = clean_json_markdown(raw_content)
    try:
        return json.loads(cleaned)
    except Exception:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(cleaned[start:end+1])
            except Exception:
                pass
    return None

def call_vultr_inference(messages: List[Dict[str, Any]], model_name: str, config: Dict[str, str]) -> Optional[str]:
    """Executes call to Vultr Serverless Inference with response_format fallback."""
    client = OpenAI(
        base_url=config["base_url"],
        api_key=config["api_key"],
        timeout=30.0
    )
    # Attempt 1: with json_object format
    try:
        resp = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0.1,
            response_format={"type": "json_object"}
        )
        if resp.choices and resp.choices[0].message:
            return resp.choices[0].message.content
    except Exception:
        pass

    # Attempt 2: standard format
    try:
        resp = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0.1
        )
        if resp.choices and resp.choices[0].message:
            return resp.choices[0].message.content
    except Exception as err:
        print(f"Vultr inference error: {err}")
    return None

def merge_verdicts(llm_data: Optional[Dict[str, Any]], heuristic_data: Dict[str, Any], model_name: str) -> Dict[str, Any]:
    """
    Combines LLM threat analysis with deterministic code heuristics.
    Adheres to the safety principle: when in doubt, lean towards the more cautious verdict.
    """
    severity_order = {"SAFE": 1, "SUSPICIOUS": 2, "SCAM": 3}
    
    heur_verdict = heuristic_data.get("heuristic_verdict", "SAFE").upper()
    heur_score = heuristic_data.get("heuristic_score", 0)
    heur_reasons = heuristic_data.get("reasons", [])
    heur_asks = heuristic_data.get("asks_for", [])
    heur_brand = heuristic_data.get("pretending_to_be")

    if not llm_data:
        return {
            "verdict": heur_verdict,
            "confidence": round(heur_score / 100.0, 2) if heur_score > 0 else 0.95,
            "pretending_to_be": heur_brand,
            "asks_for": heur_asks,
            "reasons": heur_reasons,
            "threat_source": "Deterministic Containment Heuristics (LLM Fallback)",
            "indicators": heuristic_data.get("indicators", [])
        }

    raw_llm_verdict = str(llm_data.get("verdict", "SUSPICIOUS")).upper()
    if raw_llm_verdict not in severity_order:
        raw_llm_verdict = "SUSPICIOUS"

    llm_confidence = float(llm_data.get("confidence", 0.8))
    llm_reasons = llm_data.get("reasons", [])
    llm_brand = llm_data.get("pretending_to_be")
    llm_asks = llm_data.get("asks_for", [])

    # Lean towards the higher severity
    if severity_order.get(heur_verdict, 1) >= severity_order.get(raw_llm_verdict, 1):
        final_verdict = heur_verdict
    else:
        final_verdict = raw_llm_verdict

    combined_asks = list(dict.fromkeys(heur_asks + llm_asks))
    combined_reasons = list(dict.fromkeys(llm_reasons + heur_reasons))[:3]
    final_brand = heur_brand or llm_brand

    return {
        "verdict": final_verdict,
        "confidence": round(max(llm_confidence, heur_score / 100.0), 2),
        "pretending_to_be": final_brand,
        "asks_for": combined_asks,
        "reasons": combined_reasons if combined_reasons else ["Evaluated across DOM, network and brand boundaries."],
        "threat_source": f"Vultr Serverless Inference ({model_name}) + Heuristics",
        "indicators": heuristic_data.get("indicators", [])
    }

async def analyze_threat(result_data: Dict[str, Any], job_dir: Path) -> Dict[str, Any]:
    """
    Main analysis pipeline:
    1. Runs deterministic code heuristics.
    2. Gathers visual screenshot evidence and DOM telemetry.
    3. Queries Vultr Serverless Inference via OpenAI SDK.
    4. Combines results into final verdict.
    """
    config = get_vultr_config()
    heuristics_result = evaluate_heuristics(result_data)

    if not config["api_key"]:
        print("VULTR_INFERENCE_API_KEY not configured. Using deterministic heuristics engine.")
        return merge_verdicts(None, heuristics_result, config["model"])

    # Prepare evidence summary
    target = result_data.get("url")
    final_url = result_data.get("final_url")
    redirects = result_data.get("redirect_chain", [])
    text_snippet = result_data.get("text", "")[:2000]
    fields = result_data.get("fields", {})
    external_domains = result_data.get("external_domains", [])
    blocked_events = result_data.get("blocked_events", [])

    evidence_summary = f"""
EVIDENCE COLLECTED FROM SANDBOX DETONATION:
- Initial Target: {target}
- Final Landed URL: {final_url}
- Redirection Path: {' -> '.join(redirects)}
- Visible Page Text: {text_snippet}
- Detected Form Inputs: {json.dumps(fields.get('inputs', []))}
- Sensitive Field Counts: Password={fields.get('password', 0)}, OTP/PIN={fields.get('otp_like', 0)}, Card={fields.get('card_like', 0)}
- Outbound External Domains: {', '.join(external_domains) if external_domains else 'None'}
- Sandbox Blocked Incidents: {json.dumps(blocked_events)}
"""

    system_prompt = (
        "You are an expert cybersecurity phishing detonation analyst for Phish&Chips. "
        "Analyze the provided sandboxed browser detonation evidence. "
        "Determine if this page is pretending to be a known brand, harvesting credentials, or conducting a scam. "
        "Reply with strictly valid JSON only matching this schema:\n"
        "{\n"
        '  "verdict": "SAFE" | "SUSPICIOUS" | "SCAM",\n'
        '  "confidence": 0.0 to 1.0,\n'
        '  "pretending_to_be": "Brand name or null",\n'
        '  "asks_for": ["List", "of", "sensitive", "fields"],\n'
        '  "reasons": ["Short reason 1", "Short reason 2", "Short reason 3"]\n'
        "}"
    )

    shot1_path = job_dir / "shot1.png"
    base64_img = encode_image_base64(shot1_path)

    # Attempt 1: Vision payload (if image available)
    if base64_img:
        vision_messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": evidence_summary},
                    {"type": "image_url", "image_url": {"url": base64_img}}
                ]
            }
        ]
        try:
            raw_resp = call_vultr_inference(vision_messages, config["model"], config)
            if raw_resp:
                parsed = parse_model_json(raw_resp)
                if parsed:
                    return merge_verdicts(parsed, heuristics_result, config["model"])
        except Exception as e:
            print(f"Vision inference failed ({e}). Attempting text fallback...")

    # Attempt 2: Text-only payload fallback
    text_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": evidence_summary}
    ]
    try:
        raw_resp = call_vultr_inference(text_messages, config["model"], config)
        if raw_resp:
            parsed = parse_model_json(raw_resp)
            if parsed:
                return merge_verdicts(parsed, heuristics_result, config["model"])
    except Exception as e:
        print(f"Text inference failed: {e}")

    # Fallback to heuristics if inference call fails
    return merge_verdicts(None, heuristics_result, config["model"])
