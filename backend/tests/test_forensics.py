import os
import tarfile
from pathlib import Path
import pytest
from forensics import generate_forensic_manifest, build_forensic_tarball

def test_forensics_manifest_and_tarball(tmp_path):
    job_id = "test_forensic_01"
    job_dir = tmp_path / job_id
    job_dir.mkdir()

    # Create dummy artifacts
    (job_dir / "shot1.png").write_bytes(b"dummy_png_bytes_1")
    (job_dir / "result.json").write_text('{"verdict": "SCAM"}')
    (job_dir / "dom_snapshot.html").write_text('<html><body>Bank Login</body></html>')

    manifest = generate_forensic_manifest(job_id, job_dir)
    assert manifest["job_id"] == job_id
    assert "hmac_signature" in manifest
    assert len(manifest["files"]) >= 3
    
    file_names = [f["name"] for f in manifest["files"]]
    assert "shot1.png" in file_names
    assert "result.json" in file_names
    assert "dom_snapshot.html" in file_names
    assert all(len(f["sha256"]) == 64 for f in manifest["files"])

    tar_bytes = build_forensic_tarball(job_id, job_dir)
    assert len(tar_bytes) > 0

    # Verify tarball structure
    tar_path = tmp_path / "test.tar.gz"
    tar_path.write_bytes(tar_bytes)
    with tarfile.open(tar_path, "r:gz") as tar:
        names = tar.getnames()
        assert any("manifest.json" in n for n in names)
        assert any("shot1.png" in n for n in names)

