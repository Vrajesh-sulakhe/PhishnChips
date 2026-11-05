"""
events.py - Structured Containment Event Logging & SSE Broadcaster for Phish&Chips.
Maintains timestamped execution traces to prove isolation guarantees to users and judges.
Supports asynchronous subscription for real-time Server-Sent Events (SSE).
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import asyncio
import threading

_lock = threading.Lock()
_job_events: Dict[str, List[Dict[str, Any]]] = {}
_job_subscribers: Dict[str, List[asyncio.Queue]] = {}

def init_job_events(job_id: str):
    """Initializes the event log for a given job ID."""
    with _lock:
        _job_events[job_id] = []
        _job_subscribers[job_id] = []

def determine_stage(msg: str, explicit_stage: Optional[str]) -> str:
    if explicit_stage:
        return explicit_stage
    m = msg.upper()
    if "CONTAINER CREATED" in m or "SPUN UP" in m:
        return "SANDBOX_INIT"
    if "LIMITS APPLIED" in m or "ENFORCED" in m or "CAP-DROP" in m:
        return "CAP_DROP"
    if "DETONATING" in m or "OPENING" in m or "NAVIGAT" in m:
        return "NAVIGATING"
    if "BLOCKED" in m or "INTERCEPT" in m or "DROPPED" in m:
        return "INTERCEPT"
    if "CAPTURED" in m or "SCREENSHOT" in m or "DOM" in m:
        return "EVIDENCE_COLLECTED"
    if "PAUSING FOR HUMAN" in m or "AWAITING" in m:
        return "AWAITING_APPROVAL"
    if "AUTHORIZED DUMMY" in m or "SUBMISSION PASS" in m:
        return "P2_INIT"
    if "VULTR INFERENCE" in m or "SYNTHESIZING" in m or "DISPATCHING" in m:
        return "INFERENCE_DISPATCH"
    if "CONTAINER DESTROYED" in m:
        return "CONTAINER_DESTROYED"
    if "PHISH FRIED" in m or "FINALIZED" in m or "DONE" in m:
        return "DONE"
    return "INFO"

def log_event(job_id: str, msg: str, stage: Optional[str] = None, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Records an immutable containment event entry with UTC timestamp and broadcasts to SSE listeners."""
    now = datetime.now(timezone.utc)
    assigned_stage = determine_stage(msg, stage)
    entry = {
        "stage": assigned_stage,
        "message": msg,
        "msg": msg, # backwards-compat
        "time": now.strftime("%H:%M:%S"),
        "ts": now.isoformat(),
        "data": data or {}
    }

    subscribers_to_notify = []
    with _lock:
        if job_id not in _job_events:
            _job_events[job_id] = []
        _job_events[job_id].append(entry)
        if job_id in _job_subscribers:
            subscribers_to_notify = list(_job_subscribers[job_id])

    for q in subscribers_to_notify:
        try:
            q.put_nowait(entry)
        except Exception:
            pass

    return entry

def get_events(job_id: str) -> List[Dict[str, Any]]:
    """Retrieves all logged events for a given job ID."""
    with _lock:
        return list(_job_events.get(job_id, []))

def subscribe_job_events(job_id: str) -> asyncio.Queue:
    """Registers an async queue to receive real-time events for SSE."""
    q = asyncio.Queue()
    with _lock:
        past_events = list(_job_events.get(job_id, []))
        if job_id not in _job_subscribers:
            _job_subscribers[job_id] = []
        _job_subscribers[job_id].append(q)

    # Replay historical events
    for ev in past_events:
        q.put_nowait(ev)
    return q

def unsubscribe_job_events(job_id: str, q: asyncio.Queue):
    """Unregisters an async queue after SSE connection closes."""
    with _lock:
        if job_id in _job_subscribers and q in _job_subscribers[job_id]:
            _job_subscribers[job_id].remove(q)

def clear_job_events(job_id: str):
    """Purges events for a given job ID after retention expires."""
    with _lock:
        _job_events.pop(job_id, None)
        _job_subscribers.pop(job_id, None)
