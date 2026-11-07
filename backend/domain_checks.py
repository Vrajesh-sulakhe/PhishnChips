"""
domain_checks.py - Apex ownership corroboration (DNS, TLS certificate, RDAP age).

Every probe is bounded by a short timeout and returns *unknown* (None) on failure.
Failure to corroborate is never evidence of maliciousness; it only withholds the
"verified owner" grounding signal. Results are cached per apex (TTL) to bound cost.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from reputation import apex_domain, extract_host

PROBE_TIMEOUT = 1.5
CACHE_TTL_SECONDS = 6 * 3600
_cache: Dict[str, tuple] = {}


def _public_ips(host: str) -> Optional[list]:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    ips = sorted({i[4][0] for i in infos})
    for ip in ips:
        a = ipaddress.ip_address(ip)
        if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast:
            return []  # resolves into private space: never probe
    return ips


def _tls_subject_org(host: str) -> Optional[Dict[str, Any]]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=PROBE_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError):
        return {"valid": False}
    subject = {k: v for rdn in cert.get("subject", ()) for k, v in rdn}
    issuer = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
    return {
        "valid": True,
        "organization": subject.get("organizationName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "not_after": cert.get("notAfter"),
    }


def _rdap_age_days(apex: str) -> Optional[int]:
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{apex}", headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT * 2) as resp:
            data = json.loads(resp.read(200_000))
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return max(0, (datetime.now(timezone.utc) - created).days)
    except Exception:
        return None
    return None


def _probe(host: str) -> Dict[str, Any]:
    apex = apex_domain(host)
    ips = _public_ips(host)
    info: Dict[str, Any] = {"apex": apex, "resolves": ips is not None and len(ips) > 0, "ips": (ips or [])[:4]}
    if ips:
        info["tls"] = _tls_subject_org(host)
        info["age_days"] = _rdap_age_days(apex)
    else:
        info["tls"] = None
        info["age_days"] = None
    return info


async def corroborate_apex(url_or_host: str, budget: float = 3.0) -> Dict[str, Any]:
    """Best-effort ownership evidence for the landing host; always returns within `budget`."""
    host = extract_host(url_or_host)
    if not host:
        return {"apex": "", "resolves": False, "tls": None, "age_days": None}
    hit = _cache.get(host)
    if hit and time.time() - hit[0] < CACHE_TTL_SECONDS:
        return hit[1]
    try:
        info = await asyncio.wait_for(asyncio.to_thread(_probe, host), timeout=budget)
    except (asyncio.TimeoutError, Exception):
        return {"apex": apex_domain(host), "resolves": None, "tls": None, "age_days": None, "timed_out": True}
    _cache[host] = (time.time(), info)
    return info


def is_newly_registered(info: Dict[str, Any], threshold_days: int = 30) -> bool:
    age = info.get("age_days")
    return age is not None and age < threshold_days

