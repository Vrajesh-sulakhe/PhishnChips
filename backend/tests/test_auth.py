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

