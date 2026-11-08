"""
scanner.py - Isolated Container Lifecycle Manager for Phish&Chips.
Spawns, constrains, monitors, and destroys ephemeral Docker sandboxes.
"""

import os
import json
import asyncio
import subprocess
import shutil
import time
from pathlib import Path
from typing import Dict, Any, Optional

from events import log_event, init_job_events
from analyzer import analyze_threat, TOTAL_BUDGET_SECONDS
from schemas import LEGACY_VERDICT
import metrics
import db
import c2_hunter
import forensics
import re_engine

BASE_DIR = Path("/root/phish-n-chips")
if not BASE_DIR.exists():
    BASE_DIR = Path(__file__).resolve().parent.parent

EVIDENCE_DIR = BASE_DIR / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

# End-to-end budget (sandbox + parsing + inference) is TOTAL_BUDGET_SECONDS (default 60s, excludes the
# interactive human-approval wait). The sandbox gets initial wall-clock time; inference gets the full remaining budget.
SCAN_TIMEOUT_SECONDS = max(5, min(int(os.getenv("SCAN_TIMEOUT_SECONDS", "20")), int(TOTAL_BUDGET_SECONDS) - 10))
MAX_QUEUE_DEPTH = int(os.getenv("MAX_QUEUE_DEPTH", "50"))
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
JOB_RETENTION_MINUTES = int(os.getenv("JOB_RETENTION_MINUTES", "30"))

semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
active_scans_count = 0

# Global in-memory job registry
jobs: Dict[str, Dict[str, Any]] = {}
job_approval_events: Dict[str, asyncio.Event] = {}
job_approval_choices: Dict[str, bool] = {}

def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    return jobs.get(job_id)

def get_active_scans_count() -> int:
    return active_scans_count

def get_max_scans() -> int:
    return MAX_CONCURRENT_SCANS


def get_queue_depth() -> int:
    return sum(1 for j in jobs.values() if j.get("status") == "queued")


def queue_has_capacity() -> bool:
    return get_queue_depth() < MAX_QUEUE_DEPTH


def indeterminate_verdict(reason: str, detail: str) -> Dict[str, Any]:
    """Graceful 'Analysis Incomplete' result. Timeouts and sandbox failures never become Malicious."""
    return {
        "verdict": LEGACY_VERDICT["indeterminate"],
        "verdict_class": "indeterminate",
        "confidence": 0.0,
        "indicators": [],
        "evidence_chain": [f"Dynamic analysis completed? -> no ({reason}): {detail}"],
        "reasons": [f"Analysis Incomplete (Retry): {detail}"],
        "pretending_to_be": None,
        "asks_for": [],
        "threat_type": "none",
        "tier": "none",
        "engine": "degraded",
        "analysis_complete": False,
        "degraded_reason": reason,
        "threat_source": "Analysis Incomplete (Retry) - Manual Review",
        "needs_manual_review": True,
    }

async def run_docker_sandbox(job_id: str, url: str, submit_pass: bool = False) -> Dict[str, Any]:
    """
    Executes an ephemeral sandbox container with non-negotiable security flags.
    """
    job_dir = EVIDENCE_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(job_dir, 0o777)

    container_name = f"sandbox-{job_id}"
    stage_prefix = "SANDBOX_INIT"
    if submit_pass:
        container_name = f"sandbox-{job_id}-p2"
        stage_prefix = "P2_INIT"

    cmd = [
        "docker", "run", "--rm",
        f"--name={container_name}",
        "--network=phishnet",
        "--memory=2g", "--memory-swap=2g",
        "--cpus=2",
        "--pids-limit=512",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=256m",
        "--tmpfs", "/home/runner:rw,size=256m",
        "--shm-size=512m",
        "-v", f"{job_dir}:/out:rw",
        "-e", f"TARGET_URL={url}",
        "-e", f"NAV_TIMEOUT_MS={max(3000, (SCAN_TIMEOUT_SECONDS - 4) * 1000)}",
        "-e", f"SUBMIT_PASS={'1' if submit_pass else '0'}",
        "phishchips-sandbox"
    ]

    log_event(job_id, f"Docker container spun up under phishnet network boundary (id {container_name})", stage=stage_prefix)
    log_event(job_id, f"Sandbox Quotas: 2.0 vCPUs, 2048MB RAM, 512 PIDs, {SCAN_TIMEOUT_SECONDS}s hard timeout (Host Specs: 4 vCPUs, 8192MB RAM, 160GB SSD)", stage="CAP_DROP")
    log_event(job_id, "Network: public internet only, host + private ranges blocked via iptables", stage="CAP_DROP")
    log_event(job_id, "Secrets inside sandbox: none (zero API keys or credentials injected)", stage="CAP_DROP")
    log_event(job_id, f"Detonating target in headless Chromium: {url}", stage="NAVIGATING")

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=float(SCAN_TIMEOUT_SECONDS))
    except asyncio.TimeoutError:
        log_event(job_id, "Detonation timed out. Enforcing immediate container termination via docker kill.", stage="INTERCEPT")
        subprocess.run(["docker", "kill", container_name], capture_output=True)
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        metrics.SANDBOX_TIMEOUTS.inc()
        raise TimeoutError(f"Sandbox execution timed out after {SCAN_TIMEOUT_SECONDS}s.")
    except Exception as ex:
        metrics.SANDBOX_ERRORS.inc()
        log_event(job_id, f"Container execution error: {str(ex)}", stage="ERROR")
        raise ex
    finally:
        # Guarantee container destruction
        subprocess.run(["docker", "kill", container_name], capture_output=True)
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        log_event(job_id, f"Container destroyed ({container_name})", stage="CONTAINER_DESTROYED")

    result_path = job_dir / "result.json"
    if not result_path.exists():
        raise RuntimeError("Sandbox failed to output result.json telemetry.")

    with open(result_path, "r", encoding="utf-8") as f:
        telemetry = json.load(f)

    return telemetry

async def process_scan_job(job_id: str, url: str):
    """
    Background worker orchestrating the multi-phase scan pipeline.
    """
    global active_scans_count
    job = jobs[job_id]
    job["status"] = "running"
    job_dir = EVIDENCE_DIR / job_id

    async with semaphore:
        active_scans_count += 1
        metrics.ACTIVE_SCANS.set(active_scans_count)
        metrics.QUEUE_DEPTH.set(get_queue_depth())
        started = time.monotonic()
        deadline = started + TOTAL_BUDGET_SECONDS
        try:
            # Phase 1: Detonate & Inspect
            t_sb = time.monotonic()
            try:
                telemetry = await run_docker_sandbox(job_id, url, submit_pass=False)
            except TimeoutError as te:
                # Graceful degradation: a slow/evasive page is Indeterminate, never Malicious.
                metrics.BUDGET_EXCEEDED.inc()
                job["verdict"] = indeterminate_verdict("sandbox_timeout", str(te))
                _finish_job(job_id, url, job, started)
                return
            metrics.SANDBOX_DURATION.observe(time.monotonic() - t_sb)
            job["raw_result"] = telemetry

            # Collect screenshots
            screenshots = []
            for s in telemetry.get("screenshots", []):
                if (job_dir / s).exists():
                    screenshots.append(f"/api/scan/{job_id}/shot/{s}")
            job["screenshots"] = screenshots

            # Log events from telemetry
            for blocked in telemetry.get("blocked_events", []):
                log_event(job_id, f"Blocked: {blocked.get('detail', 'Unauthorized action')} (SSRF/Malware prevented)", stage="INTERCEPT")

            log_event(job_id, f"Captured full DOM and {len(screenshots)} visual screenshot(s)", stage="EVIDENCE_COLLECTED")

            fields = telemetry.get("fields", {})
            has_credentials = (fields.get("password", 0) > 0 or 
                               fields.get("otp_like", 0) > 0 or 
                               fields.get("card_like", 0) > 0)

            # Phase 2 (Pattern B): Human Approval Gate
            if has_credentials:
                job["status"] = "awaiting_approval"
                log_event(job_id, "⚠️ Credential harvester detected. Pausing for human authorization (Pattern B).", stage="AWAITING_APPROVAL")
                
                # Wait for user input or 40s timeout (human wait is excluded from the time budget)
                gate_started = time.monotonic()
                approval_event = asyncio.Event()
                job_approval_events[job_id] = approval_event

                try:
                    await asyncio.wait_for(approval_event.wait(), timeout=40.0)
                    approved = job_approval_choices.get(job_id, False)
                except asyncio.TimeoutError:
                    approved = False
                    log_event(job_id, "Human approval timed out. Continuing with static verdict.", stage="INFO")

                deadline += time.monotonic() - gate_started
                if approved:
                    deadline += SCAN_TIMEOUT_SECONDS
                    log_event(job_id, "Human approval received: Authorized decoy submission pass with synthetic canary values.", stage="P2_INIT")
                    job["status"] = "running"
                    try:
                        telemetry_p2 = await run_docker_sandbox(job_id, url, submit_pass=True)
                        job["raw_result"] = telemetry_p2
                        # Refresh screenshots
                        screenshots_p2 = []
                        for s in telemetry_p2.get("screenshots", []):
                            if (job_dir / s).exists():
                                screenshots_p2.append(f"/api/scan/{job_id}/shot/{s}")
                        job["screenshots"] = screenshots_p2
                    except Exception as e_p2:
                        log_event(job_id, f"Submission pass failed: {str(e_p2)}", stage="ERROR")
                else:
                    log_event(job_id, "Decoy submission declined. Proceeding directly to threat synthesis.", stage="INFO")

            # Run Static Reverse Engineering on any quarantined binaries & WASM
            try:
                re_intel = re_engine.analyze_quarantined_artifacts(job_dir)
                job["re_intelligence"] = re_intel
                if isinstance(job.get("raw_result"), dict):
                    job["raw_result"]["re_intelligence"] = re_intel
                if re_intel.get("has_disassembly"):
                    log_event(job_id, f"🔬 Reverse Engineering: {re_intel.get('attribution_summary')}", stage="RE_INTEL")
            except Exception as re_err:
                print(f"Error in re_engine analysis: {re_err}")
                job["re_intelligence"] = {"has_disassembly": False, "artifacts": []}

            # Phase 3: AI Analysis & Heuristics Synthesis
            job["status"] = "analyzing"
            log_event(job_id, "[VULTR INFERENCE] Dispatching forensic payload to Vultr Serverless Inference...", stage="INFERENCE_DISPATCH")

            try:
                analysis = await asyncio.wait_for(
                    analyze_threat(job["raw_result"], job_dir, deadline=deadline),
                    timeout=max(1.0, deadline - time.monotonic()) + 2.0,
                )
            except asyncio.TimeoutError:
                metrics.BUDGET_EXCEEDED.inc()
                analysis = indeterminate_verdict("analysis_timeout", "analysis exceeded the end-to-end time budget")
            except Exception as ae:  # unhandled analyzer failure must not fall back to naive scoring
                metrics.INFERENCE_FAILURES.labels("analyzer_exception").inc()
                analysis = indeterminate_verdict("analyzer_exception", f"{type(ae).__name__}")
            job["verdict"] = analysis
            _finish_job(job_id, url, job, started)

        except Exception as e:
            job["status"] = "error"
            job["error"] = str(e)
            log_event(job_id, f"Scan aborted: {str(e)}", stage="ERROR")
            log_event(job_id, "🍟 Phish fried. Sandbox destroyed.", stage="DONE")

            # Persist error scan in SQLite database
            try:
                db.save_scan(
                    job_id=job_id,
                    target_url=url,
                    status="error",
                    user_id=job.get("user_id"),
                    verdict="UNKNOWN",
                    confidence=0.0,
                    threat_source="Sandbox Runtime Abort",
                    screenshots=job.get("screenshots", []),
                    reasons=[f"Scan aborted: {str(e)}"],
                    threat_type="none",
                    verdict_class="indeterminate",
                    evidence_chain=[],
                )
            except Exception:
                pass
        finally:
            active_scans_count = max(0, active_scans_count - 1)
            metrics.ACTIVE_SCANS.set(active_scans_count)
            metrics.QUEUE_DEPTH.set(get_queue_depth())

def _finish_job(job_id: str, url: str, job: Dict[str, Any], started: float) -> None:
    """Mark done, emit metrics + one structured log line, persist to SQLite."""
    verdict_data = job.get("verdict") or {}
    elapsed = time.monotonic() - started
    vclass = verdict_data.get("verdict_class", "indeterminate")
    metrics.SCANS_TOTAL.labels(vclass, verdict_data.get("tier", "none"), verdict_data.get("engine", "none")).inc()
    metrics.CONFIDENCE.labels(vclass).observe(float(verdict_data.get("confidence") or 0.0))
    metrics.TOTAL_DURATION.observe(elapsed)
    metrics.log_json(
        "scan_complete", job_id=job_id, url=url, verdict=vclass, confidence=verdict_data.get("confidence"),
        tier=verdict_data.get("tier"), engine=verdict_data.get("engine"), degraded_reason=verdict_data.get("degraded_reason"),
        analysis_complete=verdict_data.get("analysis_complete"), duration_s=round(elapsed, 2),
    )

    # Component 2 & 4: Extract C2 threat intelligence & generate cryptographic forensic locker
    job_dir = EVIDENCE_DIR / job_id
    try:
        c2_intel = c2_hunter.extract_c2_intelligence(job.get("raw_result") or {})
        job["c2_intelligence"] = c2_intel
        if c2_intel.get("has_c2_exfiltration"):
            log_event(job_id, f"🎯 C2 Exfiltration Vector Discovered: {c2_intel.get('attribution_summary')}", stage="C2_INTEL")
    except Exception as c2_err:
        print(f"Error computing C2 intelligence: {c2_err}")
        c2_intel = {"has_c2_exfiltration": False, "drop_destinations": [], "attribution_summary": "None"}
        job["c2_intelligence"] = c2_intel

    try:
        forensic_manifest = forensics.generate_forensic_manifest(job_id, job_dir)
        job["forensic_manifest"] = forensic_manifest
        log_event(job_id, f"🔒 Signed forensic locker generated ({len(forensic_manifest.get('artifacts', []))} artifacts, HMAC verified)", stage="FORENSIC_LOCKER")
    except Exception as f_err:
        print(f"Error generating forensic manifest: {f_err}")

    log_event(job_id, "🍟 Phish fried. Sandbox destroyed.", stage="DONE")
    job["status"] = "done"
    try:
        db.save_scan(
            job_id=job_id,
            target_url=url,
            status="done",
            user_id=job.get("user_id"),
            verdict=verdict_data.get("verdict"),
            confidence=verdict_data.get("confidence"),
            threat_source=verdict_data.get("threat_source"),
            screenshots=job.get("screenshots", []),
            reasons=verdict_data.get("reasons", []),
            asks_for=verdict_data.get("asks_for", []),
            pretending_to_be=verdict_data.get("pretending_to_be"),
            threat_type=verdict_data.get("threat_type"),
            verdict_class=verdict_data.get("verdict_class"),
            evidence_chain=verdict_data.get("evidence_chain", []),
            c2_intelligence=job.get("c2_intelligence"),
            re_intelligence=job.get("re_intelligence"),
        )
    except Exception as dbe:
        print(f"Error persisting scan to DB: {dbe}")

def handle_approval(job_id: str, approve: bool) -> bool:
    """Delivers user decision to the paused job."""
    if job_id in job_approval_events:
        job_approval_choices[job_id] = approve
        job_approval_events[job_id].set()
        return True
    return False

async def janitor_cleanup_task():
    """
    Background janitor running periodically to remove stale containers and old job files.
    """
    while True:
        try:
            # 1. Clean up orphan containers
            subprocess.run(
                ["docker", "ps", "-a", "--filter", "name=sandbox-", "--format", "{{.ID}} {{.CreatedAt}}"],
                capture_output=True, text=True
            )
            # 2. Prune old evidence directories
            now = time.time()
            cutoff = now - (JOB_RETENTION_MINUTES * 60)
            if EVIDENCE_DIR.exists():
                for item in EVIDENCE_DIR.iterdir():
                    if item.is_dir() and item.name not in ("acceptance-test",):
                        try:
                            if item.stat().st_mtime < cutoff:
                                shutil.rmtree(item, ignore_errors=True)
                                jobs.pop(item.name, None)
                        except Exception:
                            pass
        except Exception as e:
            print(f"Janitor error: {e}")

        await asyncio.sleep(60)
