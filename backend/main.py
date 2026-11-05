"""
main.py - FastAPI Manager & Async Orchestrator for Phish&Chips.
Handles async job dispatch, SSE event streaming, human approval gates, screenshot streaming, and demo assets.
"""

import os
import uuid
import re
import json
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response, StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from validation import validate_url, check_rate_limit, ValidationError
from events import init_job_events, get_events, subscribe_job_events, unsubscribe_job_events
import scanner

BASE_DIR = Path("/root/phish-n-chips")
if not BASE_DIR.exists():
    BASE_DIR = Path(__file__).resolve().parent.parent

FRONTEND_DIR = BASE_DIR / "frontend"
EVIDENCE_DIR = BASE_DIR / "evidence"
DEMO_DIR = BASE_DIR / "demo" / "fake-pages"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start background janitor
    janitor_task = asyncio.create_task(scanner.janitor_cleanup_task())
    yield
    janitor_task.cancel()

app = FastAPI(
    title="Phish&Chips: Ephemeral Sandbox Orchestrator",
    description="Track 01 · Blast Radius Zero // Vultr Hackathon",
    version="2.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static frontend assets
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

class ScanRequest(BaseModel):
    url: str

class ApprovalRequest(BaseModel):
    approve: bool

@app.get("/")
def serve_root():
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        return {"status": "ok", "service": "Phish&Chips Backend (index.html not built yet)"}
    return FileResponse(index_file)

@app.get("/health")
@app.get("/api/health")
def health_check():
    api_key_set = bool(os.getenv("VULTR_INFERENCE_API_KEY", "").strip())
    active_sandboxes = scanner.get_active_scans_count()
    max_sandboxes = scanner.get_max_scans()
    return {
        "status": "healthy",
        "service": "phish-n-chips-backend",
        "control_plane": "Vultr BLR (4 vCPU / 8 GB)",
        "active_sandboxes": active_sandboxes,
        "max_sandboxes": max_sandboxes,
        "slots_display": f"{active_sandboxes} / {max_sandboxes} Sandboxes Active",
        "network": "phishnet (172.30.0.0/16)",
        "iptables_phishnet": "Enforced (Host & RFC1918 Dropped)",
        "inference_endpoint": "api.vultrinference.com",
        "inference_status": "Connected (api.vultrinference.com)" if api_key_set else "Standby (Deterministic Heuristics Active)",
        "sandbox_image": "phishchips-sandbox"
    }

@app.post("/api/scan")
async def start_scan(req: ScanRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded (maximum 20 scans per minute). Please try again shortly."
        )

    try:
        validated_url = validate_url(req.url)
    except ValidationError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    job_id = uuid.uuid4().hex[:8]
    init_job_events(job_id)

    scanner.jobs[job_id] = {
        "job_id": job_id,
        "target_url": validated_url,
        "status": "queued",
        "screenshots": [],
        "raw_result": None,
        "verdict": None,
        "error": None
    }

    # Dispatch background worker
    asyncio.create_task(scanner.process_scan_job(job_id, validated_url))

    return {"job_id": job_id, "status": "queued"}

@app.get("/api/scan/{job_id}/stream")
async def stream_scan_events(job_id: str):
    """Server-Sent Events (SSE) live event streaming endpoint."""
    job = scanner.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' not found.")

    async def event_generator():
        q = subscribe_job_events(job_id)
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=1.5)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get("stage") in ("DONE", "ERROR"):
                        current_job = scanner.get_job(job_id)
                        yield f"data: {json.dumps({'stage': 'JOB_SNAPSHOT', 'job': current_job})}\n\n"
                        break
                except asyncio.TimeoutError:
                    current_job = scanner.get_job(job_id)
                    if not current_job:
                        break
                    if current_job.get("status") in ("done", "error") and q.empty():
                        yield f"data: {json.dumps({'stage': 'JOB_SNAPSHOT', 'job': current_job})}\n\n"
                        break
                    # Send keep-alive comment
                    yield ": keep-alive\n\n"
        finally:
            unsubscribe_job_events(job_id, q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@app.get("/api/scan/{job_id}")
async def get_scan_status(job_id: str):
    job = scanner.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' not found.")

    events = get_events(job_id)

    return {
        "job_id": job_id,
        "target_url": job.get("target_url"),
        "status": job.get("status"),
        "events": events,
        "screenshots": job.get("screenshots", []),
        "result": job.get("verdict"),
        "raw_telemetry": job.get("raw_result"),
        "error": job.get("error")
    }

@app.post("/api/scan/{job_id}/approve")
async def approve_scan_action(job_id: str, body: ApprovalRequest):
    job = scanner.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' not found.")

    if job.get("status") != "awaiting_approval":
        raise HTTPException(status_code=400, detail="Job is not currently awaiting human authorization.")

    delivered = scanner.handle_approval(job_id, body.approve)
    return {
        "job_id": job_id,
        "approved": body.approve,
        "action_acknowledged": delivered
    }

@app.get("/api/scan/{job_id}/shot/{name}")
async def get_screenshot(job_id: str, name: str):
    # Path traversal protection
    if not re.match(r"^[a-zA-Z0-9_\-]+\.png$", name):
        raise HTTPException(status_code=400, detail="Invalid screenshot artifact identifier.")

    shot_path = EVIDENCE_DIR / job_id / name
    if not shot_path.exists():
        raise HTTPException(status_code=404, detail="Screenshot artifact not found.")

    return FileResponse(shot_path, media_type="image/png")

# Demo Endpoints
@app.get("/demo/fake-bank")
def serve_fake_bank():
    fake_page = DEMO_DIR / "bank_login.html"
    if not fake_page.exists():
        raise HTTPException(status_code=404, detail="Demo page not found.")
    return FileResponse(fake_page)

@app.get("/demo/fake-download.bin")
def serve_fake_download():
    dummy_bytes = b"MZ\x90\x00\x03\x00\x00\x00PHISHCHIPS_CANARY_PAYLOAD_TEST"
    return Response(
        content=dummy_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="ApexSecurityUpdate.exe"'}
    )
