import os
import sys
from pathlib import Path

import pytest

# Isolate from the developer's .env BEFORE analyzer imports (load_dotenv never overrides set vars).
os.environ["VULTR_INFERENCE_API_KEY"] = ""
os.environ["VULTR_API_KEY"] = ""

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "golden"))


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Tests never touch DNS/TLS/RDAP."""
    import analyzer

    async def fake_corroborate(url, budget=3.0):
        return {"apex": "", "resolves": None, "tls": None, "age_days": None}

    monkeypatch.setattr(analyzer, "corroborate_apex", fake_corroborate)
    monkeypatch.setenv("VULTR_INFERENCE_API_KEY", "")

