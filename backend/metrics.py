"""
metrics.py - Prometheus metrics + structured JSON logging for the scan pipeline.

Exposes: inference latency, sandbox duration/timeouts, schema violations (model-drift proxy),
verdict distribution, confidence distribution, fast-path hits, queue depth.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any, Dict

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

REGISTRY = CollectorRegistry()

SCANS_TOTAL = Counter("phishchips_scans_total", "Completed scans", ["verdict", "tier", "engine"], registry=REGISTRY)
FAST_PATH_TOTAL = Counter("phishchips_reputation_fast_path_total", "Reputation gate outcomes", ["outcome"], registry=REGISTRY)
SANDBOX_TIMEOUTS = Counter("phishchips_sandbox_timeouts_total", "Sandbox wall-clock timeouts", registry=REGISTRY)
SANDBOX_ERRORS = Counter("phishchips_sandbox_errors_total", "Sandbox runtime errors", registry=REGISTRY)
INFERENCE_FAILURES = Counter("phishchips_inference_failures_total", "Inference failures", ["reason"], registry=REGISTRY)
SCHEMA_VIOLATIONS = Counter("phishchips_schema_violations_total", "Model output schema violations (drift proxy)", registry=REGISTRY)
BUDGET_EXCEEDED = Counter("phishchips_budget_exceeded_total", "Jobs that exceeded the end-to-end time budget", registry=REGISTRY)
INFERENCE_LATENCY = Histogram(
    "phishchips_inference_latency_seconds", "Model inference latency", registry=REGISTRY,
    buckets=(0.25, 0.5, 1, 2, 3, 5, 8, 12, 20),
)
SANDBOX_DURATION = Histogram(
    "phishchips_sandbox_duration_seconds", "Sandbox detonation duration", registry=REGISTRY,
    buckets=(1, 2, 4, 6, 8, 10, 12, 15, 20, 30),
)
TOTAL_DURATION = Histogram(
    "phishchips_scan_duration_seconds", "End-to-end scan duration (excl. human approval wait)", registry=REGISTRY,
    buckets=(1, 2, 4, 6, 8, 10, 12, 15, 20, 30),
)
CONFIDENCE = Histogram(
    "phishchips_verdict_confidence", "Verdict confidence distribution", ["verdict"], registry=REGISTRY,
    buckets=(0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0),
)
ACTIVE_SCANS = Gauge("phishchips_active_scans", "Sandboxes currently running", registry=REGISTRY)
QUEUE_DEPTH = Gauge("phishchips_queue_depth", "Jobs waiting for a sandbox slot", registry=REGISTRY)

_log = logging.getLogger("phishchips.telemetry")
if not _log.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(_h)
    _log.setLevel(logging.INFO)
    _log.propagate = False


def log_json(event: str, **fields: Any) -> None:
    """One structured JSON log line per event (grep/ship-friendly)."""
    _log.info(json.dumps({"ts": round(time.time(), 3), "event": event, **fields}, default=str))


def render() -> tuple:
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def snapshot() -> Dict[str, Any]:
    """Small JSON summary for /api/health (full detail lives at /metrics)."""
    out: Dict[str, Any] = {}
    for fam in REGISTRY.collect():
        if fam.name in ("phishchips_scans", "phishchips_sandbox_timeouts", "phishchips_schema_violations",
                        "phishchips_budget_exceeded", "phishchips_reputation_fast_path"):
            out[fam.name] = {
                ",".join(f"{k}={v}" for k, v in s.labels.items()) or "total": s.value
                for s in fam.samples if s.name.endswith("_total")
            }
    return out

