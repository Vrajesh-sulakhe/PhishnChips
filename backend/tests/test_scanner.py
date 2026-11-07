import json

import pytest

import scanner
from events import init_job_events
from test_pipeline import WIKI


def _job(job_id, url):
    init_job_events(job_id)
    scanner.jobs[job_id] = {"job_id": job_id, "target_url": url, "status": "queued", "screenshots": [], "raw_result": None, "verdict": None, "error": None}
    return scanner.jobs[job_id]


@pytest.fixture(autouse=True)
def _no_db(monkeypatch):
    monkeypatch.setattr(scanner.db, "save_scan", lambda **kw: None)


async def test_sandbox_timeout_yields_indeterminate_not_error_or_malicious(monkeypatch):
    async def boom(job_id, url, submit_pass=False):
        raise TimeoutError("Sandbox execution timed out after 14s.")

    monkeypatch.setattr(scanner, "run_docker_sandbox", boom)
    job = _job("t-timeout", "https://slow-evasive.example/")
    await scanner.process_scan_job("t-timeout", "https://slow-evasive.example/")
    assert job["status"] == "done"
    assert job["verdict"]["verdict_class"] == "indeterminate" and job["verdict"]["verdict"] == "INDETERMINATE"
    assert job["verdict"]["analysis_complete"] is False


async def test_wikipedia_end_to_end_is_benign(monkeypatch):
    async def fake(job_id, url, submit_pass=False):
        return json.loads(json.dumps(WIKI))

    monkeypatch.setattr(scanner, "run_docker_sandbox", fake)
    job = _job("t-wiki", "https://wikipedia.org")
    await scanner.process_scan_job("t-wiki", "https://wikipedia.org")
    assert job["status"] == "done" and job["verdict"]["verdict"] == "SAFE" and job["verdict"]["tier"] == "tier1"


async def test_analyzer_crash_never_becomes_malicious(monkeypatch):
    async def fake(job_id, url, submit_pass=False):
        return json.loads(json.dumps(WIKI))

    async def crash(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(scanner, "run_docker_sandbox", fake)
    monkeypatch.setattr(scanner, "analyze_threat", crash)
    job = _job("t-crash", "https://wikipedia.org")
    await scanner.process_scan_job("t-crash", "https://wikipedia.org")
    assert job["verdict"]["verdict_class"] == "indeterminate"
