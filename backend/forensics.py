"""
forensics.py - Cryptographic Forensic Evidence Vault & Chain of Custody for Phish&Chips.
Computes SHA-256 hashes of all detonation artifacts, generates HMAC-signed manifests,
and packages tamper-proof evidence tarballs for SOC/legal admissibility.
"""

import os
import io
import json
import hmac
import hashlib
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

HMAC_SECRET = os.getenv("SESSION_SECRET", "phishchips_forensic_evidence_hmac_secret_2026").encode("utf-8")

def compute_file_sha256(file_path: Path) -> str:
    """Computes SHA-256 hex digest for a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def generate_forensic_manifest(job_id: str, job_dir: Path) -> Dict[str, Any]:
    """
    Scans the detonation job directory, computes SHA-256 checksums of all forensic assets,
    and produces an HMAC-SHA256 signed chain-of-custody manifest.
    """
    files_list: List[Dict[str, Any]] = []
    
    if job_dir.exists():
        for p in sorted(job_dir.glob("*")):
            if p.is_file() and p.name not in ("manifest.json", "evidence.tar.gz"):
                try:
                    size = p.stat().st_size
                    sha = compute_file_sha256(p)
                    files_list.append({
                        "name": p.name,
                        "size_bytes": size,
                        "sha256": sha
                    })
                except Exception as ex:
                    print(f"Error hashing {p}: {ex}")

    now_iso = datetime.now(timezone.utc).isoformat()
    
    # Calculate a composite hash across all files for signing
    composite = "|".join(f"{f['name']}:{f['sha256']}" for f in files_list)
    signature = hmac.new(HMAC_SECRET, composite.encode("utf-8"), hashlib.sha256).hexdigest()

    manifest = {
        "job_id": job_id,
        "investigation_id": f"DET-{job_id.upper()}",
        "timestamp": now_iso,
        "control_plane": "Vultr Cloud Compute BLR (4 vCPUs / 8192 MB RAM / 160 GB SSD)",
        "network_boundary": "phishnet (172.30.0.0/16) - Drop Host & RFC1918",
        "total_artifacts": len(files_list),
        "files": files_list,
        "hmac_signature": signature
    }

    manifest_path = job_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest

def build_forensic_tarball(job_id: str, job_dir: Path) -> bytes:
    """
    Builds a gzip-compressed tar archive containing all job artifacts and the signed manifest.
    Returns the binary tarball bytes for streaming download.
    """
    # Ensure manifest exists
    generate_forensic_manifest(job_id, job_dir)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in sorted(job_dir.glob("*")):
            if p.is_file() and not p.name.endswith(".tar.gz"):
                tar.add(p, arcname=f"DET-{job_id.upper()}/{p.name}")

    buf.seek(0)
    return buf.getvalue()

