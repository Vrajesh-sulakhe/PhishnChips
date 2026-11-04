"""
events.py - Structured Containment Event Logging for Phish&Chips.
Maintains timestamped execution traces to prove isolation guarantees to users and judges.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
import threading

_lock = threading.Lock()
_job_events: Dict[str, List[Dict[str, str]]] = {}

def init_job_events(job_id: str):
    """Initializes the event log for a given job ID."""
    with _lock:
        _job_events[job_id] = []

def log_event(job_id: str, msg: str) -> Dict[str, str]:
    """Records an immutable containment event entry with UTC timestamp."""
    now = datetime.now(timezone.utc)
    entry = {
        "ts": now.isoformat(),
        "time": now.strftime("%H:%M:%S"),
        "msg": msg
    }
    with _lock:
        if job_id not in _job_events:
            _job_events[job_id] = []
        _job_events[job_id].append(entry)
    return entry

def get_events(job_id: str) -> List[Dict[str, str]]:
    """Retrieves all logged events for a given job ID."""
    with _lock:
        return list(_job_events.get(job_id, []))

def clear_job_events(job_id: str):
    """Purges events for a given job ID after retention expires."""
    with _lock:
        _job_events.pop(job_id, None)
