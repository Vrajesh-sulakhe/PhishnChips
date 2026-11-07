import os
import pytest
from fastapi.testclient import TestClient

import main
import db

@pytest.fixture(autouse=True)
def _test_db(tmp_path, monkeypatch):
    """Use an isolated SQLite test database."""
    test_db = tmp_path / "test_phishchips.db"
    monkeypatch.setattr(db, "DB_PATH", test_db)
    db.init_db()

def test_password_hashing_and_verification():
    pw = "SuperSecureP@ssw0rd123"
    pw_hash, salt = db.hash_password(pw)
    assert pw_hash != pw
    assert len(salt) == 32
    assert db.verify_password(pw, pw_hash, salt) is True
    assert db.verify_password("WrongPassword!", pw_hash, salt) is False
    assert db.verify_password("", pw_hash, salt) is False

def test_email_registration_and_login_flow():
    client = TestClient(main.app)

    # 1. Register a new user
    reg_resp = client.post("/api/auth/register", json={
        "email": "analyst@security.org",
        "password": "StrongPassword2026!",
        "name": "Jane Security"
    })
    assert reg_resp.status_code == 200
    data = reg_resp.json()
    assert data["authenticated"] is True
    assert data["user"]["email"] == "analyst@security.org"
    assert data["user"]["name"] == "Jane Security"
    assert "password_hash" not in data["user"]
    assert "salt" not in data["user"]
    assert "phishchips_session" in reg_resp.cookies

    # 2. Reject duplicate email registration
    dup_resp = client.post("/api/auth/register", json={
        "email": "analyst@security.org",
        "password": "AnotherPassword!",
        "name": "Impostor"
    })
    assert dup_resp.status_code == 400
    assert "already exists" in dup_resp.json()["detail"]

    # 3. Successful login
    login_resp = client.post("/api/auth/login", json={
        "email": "analyst@security.org",
        "password": "StrongPassword2026!"
    })
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["authenticated"] is True
    assert login_data["user"]["email"] == "analyst@security.org"

    # 4. Failed login with wrong password
    bad_login = client.post("/api/auth/login", json={
        "email": "analyst@security.org",
        "password": "WrongPassword!"
    })
    assert bad_login.status_code == 401

    # 5. Failed login with non-existent user
    non_existent = client.post("/api/auth/login", json={
        "email": "unknown@domain.com",
        "password": "StrongPassword2026!"
    })
    assert non_existent.status_code == 401

def test_demo_endpoint_is_deprecated():
    client = TestClient(main.app)
    resp = client.post("/api/auth/demo")
    assert resp.status_code == 410
    assert "deprecated" in resp.json()["detail"].lower()

def test_admin_access_register():
    client = TestClient(main.app)
    resp = client.get("/api/admin/register")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["total_systems"] >= 4
    systems = [s["system_or_tool"] for s in data["register"]]
    assert any("Vultr Cloud Compute" in s for s in systems)
    assert any("Google Cloud Platform" in s for s in systems)
    assert any("Vultr Serverless" in s for s in systems)
    assert any("SQLite" in s for s in systems)


def test_account_specific_scans_isolation():
    """Verify that recent scans are strictly scoped to the authenticated account."""
    client1 = TestClient(main.app)
    client2 = TestClient(main.app)
    anon_client = TestClient(main.app)

    # 1. Register User A and User B
    r1 = client1.post("/api/auth/register", json={
        "email": "userA@phishchips.test",
        "password": "PasswordUserA123!",
        "name": "User Alpha"
    })
    user_a_id = r1.json()["user"]["id"]

    r2 = client2.post("/api/auth/register", json={
        "email": "userB@phishchips.test",
        "password": "PasswordUserB123!",
        "name": "User Beta"
    })
    user_b_id = r2.json()["user"]["id"]

    # 2. Persist scans for each user
    db.save_scan(
        job_id="job_alpha_01",
        target_url="https://alpha-threat.com",
        status="done",
        user_id=user_a_id,
        verdict="SCAM",
        confidence=0.95,
        threat_type="credential_harvest",
        verdict_class="malicious"
    )
    db.save_scan(
        job_id="job_beta_01",
        target_url="https://beta-safe.org",
        status="done",
        user_id=user_b_id,
        verdict="SAFE",
        confidence=0.99,
        threat_type="none",
        verdict_class="benign"
    )

    # 3. Anonymous visitor receives an empty list (no leakage)
    anon_res = anon_client.get("/api/scans/recent")
    assert anon_res.status_code == 200
    assert anon_res.json()["scans"] == []

    # 4. User A only sees User A's scans
    res_a = client1.get("/api/scans/recent")
    assert res_a.status_code == 200
    scans_a = res_a.json()["scans"]
    assert len(scans_a) == 1
    assert scans_a[0]["job_id"] == "job_alpha_01"
    assert scans_a[0]["target_url"] == "https://alpha-threat.com"

    # 5. User B only sees User B's scans
    res_b = client2.get("/api/scans/recent")
    assert res_b.status_code == 200
    scans_b = res_b.json()["scans"]
    assert len(scans_b) == 1
    assert scans_b[0]["job_id"] == "job_beta_01"
    assert scans_b[0]["target_url"] == "https://beta-safe.org"


