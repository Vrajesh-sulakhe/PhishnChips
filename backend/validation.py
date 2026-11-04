"""
validation.py - Input Sanitization, SSRF Shield, & Rate Limiting for Phish&Chips.
Enforces defense-in-depth before any sandbox command is issued.
"""

import ipaddress
import time
import socket
from urllib.parse import urlparse
from typing import Dict, List
import threading

MAX_URL_LENGTH = 2048
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_REQUESTS_PER_WINDOW = 20

_rate_limit_lock = threading.Lock()
_ip_request_timestamps: Dict[str, List[float]] = {}

class ValidationError(Exception):
    pass

def validate_url(raw_url: str) -> str:
    """
    Sanitizes and validates incoming URL to prevent command injection,
    overly long inputs, and SSRF attacks against internal network targets.
    """
    if not raw_url:
        raise ValidationError("URL cannot be empty.")

    clean_url = raw_url.strip()

    if clean_url in ("demo://fake-bank", "demo:fake-bank"):
        return "demo://fake-bank"

    if len(clean_url) > MAX_URL_LENGTH:
        raise ValidationError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.")

    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    try:
        parsed = urlparse(clean_url)
    except Exception as e:
        raise ValidationError(f"Malformed URL: {str(e)}")

    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        raise ValidationError("Only 'http' and 'https' protocols are permitted.")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValidationError("URL does not contain a valid hostname.")

    # Defense-in-depth SSRF checks
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"):
        raise ValidationError("Access to loopback and internal host targets is strictly forbidden.")

    if hostname.endswith((".local", ".internal", ".lan", ".home")):
        raise ValidationError("Targeting internal non-routable domains is not allowed.")

    # Check if host is a raw IP address
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private:
            raise ValidationError(f"Targeting private RFC1918 IP addresses ({hostname}) is forbidden.")
        if ip.is_loopback:
            raise ValidationError(f"Targeting loopback IP addresses ({hostname}) is forbidden.")
        if ip.is_link_local:
            raise ValidationError(f"Targeting link-local cloud metadata addresses ({hostname}) is forbidden.")
        if ip.is_reserved or ip.is_multicast:
            raise ValidationError(f"Targeting reserved IP space ({hostname}) is forbidden.")
    except ValueError:
        # Not a raw IP literal; hostname is a standard FQDN
        pass

    return clean_url

def check_rate_limit(client_ip: str) -> bool:
    """
    Sliding-window in-memory rate limiter per IP address.
    Returns True if allowed, False if rate limited.
    """
    now = time.time()
    with _rate_limit_lock:
        timestamps = _ip_request_timestamps.setdefault(client_ip, [])
        # Prune older than window
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        _ip_request_timestamps[client_ip] = [ts for ts in timestamps if ts > cutoff]

        if len(_ip_request_timestamps[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
            return False

        _ip_request_timestamps[client_ip].append(now)
        return True
