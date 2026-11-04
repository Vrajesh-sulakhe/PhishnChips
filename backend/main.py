import os
import uuid
import json
import asyncio
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import httpx

app = FastAPI(title="Phish&Chips Containment API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path("/root/phish-n-chips")
EVIDENCE_DIR = BASE_DIR / "evidence"
FRONTEND_DIR = BASE_DIR / "frontend"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static/evidence", StaticFiles(directory=str(EVIDENCE_DIR)), name="evidence")

VULTR_INFERENCE_API_KEY = os.getenv("VULTR_INFERENCE_API_KEY", "")
VULTR_INFERENCE_MODEL = os.getenv("VULTR_INFERENCE_MODEL", "llama2-13b-chat")

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    scan_id: str
    target_url: str
    status: str
    risk_score: int
    classification: str
    threat_indicators: list[str]
    analysis_summary: str
    containment_metrics: Dict[str, Any]
    artifacts: Dict[str, Optional[str]]

@app.get("/")
def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Frontend index.html not found.")
    return FileResponse(index_file)

async def query_vultr_inference(telemetry: Dict[str, Any]) -> Dict[str, Any]:
    if not VULTR_INFERENCE_API_KEY:
        has_pwd = telemetry.get("domMetadata", {}).get("hasPasswordInput", False)
        req_count = len(telemetry.get("networkRequests", []))
        score = 88 if has_pwd else (40 if req_count > 10 else 10)
        return {
            "risk_score": score,
            "classification": "Phishing / Credential Harvester" if has_pwd else "Benign Page",
            "threat_indicators": [
                "Unverified password input detected on target domain" if has_pwd else "No critical form anomalies",
                f"Generated {req_count} outbound HTTP connections during render"
            ],
            "analysis_summary": "Heuristic evaluation completed inside isolated container. Add VULTR_INFERENCE_API_KEY for deep LLM threat synthesis."
        }

    prompt = f"""
Detonation Telemetry from sandboxed execution:
Target: {telemetry.get('target')}
Final URL: {telemetry.get('finalUrl')}
DOM Metadata: {json.dumps(telemetry.get('domMetadata', {}))}
Redirect Chain: {json.dumps(telemetry.get('redirects', []))}
Network Calls: {len(telemetry.get('networkRequests', []))} outbound requests

Respond strictly in valid JSON matching this schema:
{{
  "risk_score": <int 0-100>,
  "classification": "<Benign | Phishing | Suspicious Redirect | Malware Delivery>",
  "threat_indicators": ["<indicator 1>", "<indicator 2>"],
  "analysis_summary": "<2-sentence threat summary>"
}}
"""

    headers = {
        "Authorization": f"Bearer {VULTR_INFERENCE_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": VULTR_INFERENCE_MODEL,
        "messages": [
            {"role": "system", "content": "You are a cyber security threat analyst. Output valid JSON only."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post("https://api.vultrinference.com/v1/chat/completions", headers=headers, json=payload)
            if resp.status_code == 200:
                raw_text = resp.json()["choices"][0]["message"]["content"].strip()
                if raw_text.startswith("```"):
                    raw_text = raw_text.split("```")[1].strip()
                    if raw_text.startswith("json"):
                        raw_text = raw_text[4:].strip()
                return json.loads(raw_text)
    except Exception as e:
        print(f"Inference error: {e}")

    return {
        "risk_score": 50,
        "classification": "Analysis Degraded",
        "threat_indicators": ["Inference API call failure"],
        "analysis_summary": "Sandbox telemetry acquired successfully; fallback evaluation rendered."
    }

@app.post("/api/scan", response_model=ScanResponse)
async def execute_scan(req: ScanRequest):
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scan_id = uuid.uuid4().hex[:8]
    scan_dir = EVIDENCE_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(scan_dir, 0o777)

    cmd = [
        "docker", "run", "--rm",
        f"--name=scan-{scan_id}",
        "--memory=1g",
        "--cpus=1.0",
        "--pids-limit=100",
        "--cap-drop=ALL",
        "-e", f"TARGET_URL={url}",
        "-e", "TIMEOUT_MS=15000",
        "-v", f"{scan_dir}:/output",
        "phish-sandbox"
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=25.0)
    except asyncio.TimeoutError:
        subprocess.run(["docker", "kill", f"scan-{scan_id}"], capture_output=True)
        raise HTTPException(status_code=408, detail="Sandbox execution timed out (forced containment termination).")
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Container execution failed: {str(ex)}")

    report_path = scan_dir / "report.json"
    screenshot_path = scan_dir / "screenshot.png"

    if not report_path.exists():
        raise HTTPException(status_code=500, detail="Sandbox failed to produce telemetry report.")

    with open(report_path, "r") as f:
        telemetry = json.load(f)

    threat_analysis = await query_vultr_inference(telemetry)

    return ScanResponse(
        scan_id=scan_id,
        target_url=url,
        status="completed" if not telemetry.get("error") else "errored",
        risk_score=threat_analysis.get("risk_score", 0),
        classification=threat_analysis.get("classification", "Unknown"),
        threat_indicators=threat_analysis.get("threat_indicators", []),
        analysis_summary=threat_analysis.get("analysis_summary", ""),
        containment_metrics={
            "cgroup_memory_limit": "1024MB",
            "cpu_limit": "1.0 Core",
            "capabilities_dropped": "ALL",
            "network_requests_logged": len(telemetry.get("networkRequests", [])),
            "redirects_traversed": len(telemetry.get("redirects", [])),
            "execution_error": telemetry.get("error")
        },
        artifacts={
            "screenshot_url": f"/static/evidence/{scan_id}/screenshot.png" if screenshot_path.exists() else None,
            "report_json_url": f"/static/evidence/{scan_id}/report.json"
        }
    )

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "phish-n-chips-backend"}
