"""
main.py - FastAPI Manager & Async Orchestrator for Phish&Chips.
Handles async job dispatch, SSE event streaming, human approval gates, screenshot streaming,
Google OAuth authentication, SQLite persistence, and demo assets.
"""

import os
import uuid
import re
import json
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Request, Response, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response, StreamingResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from validation import validate_url, check_rate_limit, ValidationError
from events import init_job_events, get_events, subscribe_job_events, unsubscribe_job_events
import scanner
import metrics
import reputation
import db
import auth

BASE_DIR = Path("/root/phish-n-chips")
if not BASE_DIR.exists():
    BASE_DIR = Path(__file__).resolve().parent.parent

FRONTEND_DIR = BASE_DIR / "frontend"
EVIDENCE_DIR = BASE_DIR / "evidence"
DEMO_DIR = BASE_DIR / "demo" / "fake-pages"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database with WAL mode
    db.init_db()
    # Start background janitor
    janitor_task = asyncio.create_task(scanner.janitor_cleanup_task())
    yield
    janitor_task.cancel()

app = FastAPI(
    title="Phish&Chips: Ephemeral Sandbox Orchestrator",
    description="Track 01 · Blast Radius Zero // Vultr Hackathon",
    version="2.2.0",
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

assets_dir = FRONTEND_DIR / "assets" if (FRONTEND_DIR / "assets").exists() else BASE_DIR / "assets"
if assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

fonts_dir = BASE_DIR / "fonts" if (BASE_DIR / "fonts").exists() else FRONTEND_DIR / "fonts"
if fonts_dir.exists():
    app.mount("/fonts", StaticFiles(directory=str(fonts_dir)), name="fonts")

class ScanRequest(BaseModel):
    url: str

class ApprovalRequest(BaseModel):
    approve: bool

class GoogleAuthRequest(BaseModel):
    credential: str

class EmailRegisterRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = ""

class EmailLoginRequest(BaseModel):
    email: str
    password: str

class AdminRegisterEntryRequest(BaseModel):
    admin_id: Optional[str] = None
    system_or_tool: str
    category: Optional[str] = "Security"
    main_admin: str
    backup_admin: Optional[str] = None
    department: Optional[str] = "SecOps"
    access_level: Optional[str] = "Full"
    number_of_admin_users: Optional[int] = 1
    billing_owner: Optional[str] = None
    plan: Optional[str] = None
    seats: Optional[int] = 1
    renewal_date: Optional[str] = None
    company_owned_account: Optional[bool] = True
    shared_login: Optional[bool] = False
    password_manager_entry: Optional[str] = None
    two_factor_on: Optional[bool] = True
    last_access_review: Optional[str] = None
    next_access_review: Optional[str] = None
    offboarding_checklist_item: Optional[str] = None
    risk_level: Optional[str] = "Low"
    status: Optional[str] = "Provisioned"
    notes: Optional[str] = None

@app.api_route("/", methods=["GET", "HEAD"])
def serve_root():
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        index_file = BASE_DIR / "index.html"
    if not index_file.exists():
        return {"status": "ok", "service": "Phish&Chips Backend"}
    return FileResponse(index_file)

@app.api_route("/styles.css", methods=["GET", "HEAD"])
def serve_styles_root():
    css_file = FRONTEND_DIR / "styles.css"
    if not css_file.exists():
        css_file = BASE_DIR / "styles.css"
    return FileResponse(css_file)

@app.api_route("/console.css", methods=["GET", "HEAD"])
def serve_console_css_root():
    css_file = FRONTEND_DIR / "console.css"
    if not css_file.exists():
        css_file = BASE_DIR / "console.css"
    return FileResponse(css_file)

@app.api_route("/main.js", methods=["GET", "HEAD"])
def serve_main_js_root():
    js_file = FRONTEND_DIR / "main.js"
    if not js_file.exists():
        js_file = BASE_DIR / "main.js"
    return FileResponse(js_file)

@app.api_route("/app.js", methods=["GET", "HEAD"])
def serve_app_js_root():
    js_file = FRONTEND_DIR / "app.js"
    if not js_file.exists():
        js_file = BASE_DIR / "app.js"
    return FileResponse(js_file)

@app.api_route("/console", methods=["GET", "HEAD"])
@app.api_route("/dashboard", methods=["GET", "HEAD"])
@app.api_route("/product", methods=["GET", "HEAD"])
def serve_console_root():
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        index_file = BASE_DIR / "index.html"
    return FileResponse(index_file)

@app.api_route("/login", methods=["GET", "HEAD"])
@app.api_route("/signup", methods=["GET", "HEAD"])
def serve_auth_page():
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        index_file = BASE_DIR / "index.html"
    return FileResponse(index_file)

@app.api_route("/health", methods=["GET", "HEAD"])
@app.api_route("/api/health", methods=["GET", "HEAD"])
def health_check():
    api_key_set = bool(os.getenv("VULTR_INFERENCE_API_KEY", "").strip() or os.getenv("VULTR_API_KEY", "").strip())
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
        "sandbox_image": "phishchips-sandbox",
        "database": "SQLite 3 (WAL mode)",
        "queue_depth": scanner.get_queue_depth(),
        "time_budget_seconds": scanner.TOTAL_BUDGET_SECONDS,
        "reputation_list_size": reputation.reputation_list_size(),
        "metrics": metrics.snapshot(),
    }

@app.get("/metrics")
def prometheus_metrics():
    """Prometheus scrape endpoint (inference latency, sandbox timeouts, verdict mix, drift proxies)."""
    body, content_type = metrics.render()
    return Response(content=body, media_type=content_type)

@app.get("/api/config")
def get_public_config():
    """Returns safe, public configuration for the frontend client."""
    return {
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID", "").strip(),
        "vultr_inference_active": bool(os.getenv("VULTR_INFERENCE_API_KEY", "").strip() or os.getenv("VULTR_API_KEY", "").strip()),
        "model": os.getenv("VULTR_MODEL", "llama2-13b-chat")
    }

# --- Authentication Endpoints ---

@app.post("/api/auth/google")
async def google_login(payload: GoogleAuthRequest, response: Response):
    """Authenticates or registers user using Google ID token."""
    user_info = await auth.verify_google_id_token(payload.credential)
    if not user_info or not user_info.get("email"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Google credential token."
        )

    user = db.get_or_create_user(
        email=user_info["email"],
        name=user_info.get("name", "Google Analyst"),
        avatar_url=user_info.get("avatar_url"),
        provider="google",
        provider_id=user_info.get("google_id")
    )

    session_token = db.create_session(user["id"])

    # Set HTTP-only session cookie
    response.set_cookie(
        key="phishchips_session",
        value=session_token,
        httponly=True,
        samesite="lax",
        secure=False, # Set to True in production HTTPS
        max_age=14 * 86400
    )

    return {
        "status": "ok",
        "authenticated": True,
        "token": session_token,
        "user": user
    }

@app.post("/api/auth/register")
async def register_email(payload: EmailRegisterRequest, response: Response):
    """Registers a new user account with email and password in the Vultr SQLite database."""
    try:
        user = db.register_user(
            email=payload.email,
            password=payload.password,
            name=payload.name or ""
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    session_token = db.create_session(user["id"])
    response.set_cookie(
        key="phishchips_session",
        value=session_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=14 * 86400
    )
    return {
        "status": "ok",
        "authenticated": True,
        "token": session_token,
        "user": user
    }

@app.post("/api/auth/login")
async def login_email(payload: EmailLoginRequest, response: Response):
    """Authenticates email and password credentials against the Vultr SQLite database."""
    try:
        user = db.authenticate_user(email=payload.email, password=payload.password)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password. Please check your credentials."
        )

    session_token = db.create_session(user["id"])
    response.set_cookie(
        key="phishchips_session",
        value=session_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=14 * 86400
    )
    return {
        "status": "ok",
        "authenticated": True,
        "token": session_token,
        "user": user
    }

@app.post("/api/auth/demo")
async def demo_login():
    """Demo login is deprecated. Users must sign in via Google OAuth or verified Email."""
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Demo login has been deprecated. Please sign in with Google or Email."
    )

# --- Admin Access Register Endpoints (/admin-access-register) ---

@app.get("/api/admin/register")
async def get_admin_access_register(request: Request):
    """Returns the Admin Access Register records showing system privileged access & owners."""
    user = auth.get_current_user_optional(request)
    records = db.get_admin_register()
    return {
        "status": "ok",
        "total_systems": len(records),
        "user_role": user["role"] if user else "anonymous",
        "register": records
    }

@app.post("/api/admin/register")
async def update_admin_access_register(payload: AdminRegisterEntryRequest, request: Request):
    """Adds or updates a privileged admin entry in the register."""
    user = auth.get_current_user_required(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required to modify the access register.")
    entry = db.upsert_admin_register_entry(payload.model_dump())
    return {"status": "ok", "entry": entry}

@app.get("/api/auth/me")
async def get_current_user(request: Request):
    """Returns currently authenticated user session or anonymous status."""
    user = auth.get_current_user_optional(request)
    if not user:
        return {"authenticated": False, "user": None}
    return {"authenticated": True, "user": user}

@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    """Invalidates session and clears cookie."""
    token = auth.extract_session_token(request)
    if token:
        db.delete_session(token)
    response.delete_cookie(key="phishchips_session")
    return {"status": "ok", "authenticated": False}

@app.get("/api/user/scans")
async def get_user_scans(request: Request):
    """Retrieves scans belonging to the currently logged in user."""
    user = auth.get_current_user_required(request)
    scans = db.get_user_scans(user["id"])
    return {"user_id": user["id"], "scans": scans}

@app.get("/api/scans/recent")
def get_recent_scans():
    """Retrieves platform-wide recent scan activity from SQLite database."""
    scans = db.get_recent_scans(limit=15)
    return {"scans": scans}

@app.get("/api/stats")
def get_stats():
    """Returns platform summary metrics for landing page and dashboard."""
    stats = db.get_analytics_summary()
    return stats

# --- Scan Endpoints ---

@app.post("/api/scan")
async def start_scan(req: ScanRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded (maximum 20 scans per minute). Please try again shortly."
        )

    if not scanner.queue_has_capacity():
        raise HTTPException(status_code=503, detail="Analysis queue is full. Please retry shortly.")

    try:
        validated_url = validate_url(req.url)
    except ValidationError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    user = auth.get_current_user_optional(request)
    user_id = user["id"] if user else None

    job_id = uuid.uuid4().hex[:8]
    init_job_events(job_id)

    scanner.jobs[job_id] = {
        "job_id": job_id,
        "user_id": user_id,
        "target_url": validated_url,
        "status": "queued",
        "screenshots": [],
        "raw_result": None,
        "verdict": None,
        "error": None
    }

    # Record initial queued entry in SQLite
    try:
        db.save_scan(
            job_id=job_id,
            target_url=validated_url,
            status="queued",
            user_id=user_id
        )
    except Exception as e:
        print(f"Error saving initial scan to DB: {e}")

    # Dispatch background worker
    asyncio.create_task(scanner.process_scan_job(job_id, validated_url))

    return {"job_id": job_id, "status": "queued", "user_id": user_id}

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
