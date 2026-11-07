import asyncio

import pytest

import run_golden as rg

# FP gate: < 0.1% of 500 benign samples == zero tolerated false positives.


def _run(llm):
    return asyncio.run(rg.run_offline(llm))


def test_dataset_sizes():
    assert len(rg.load("benign.jsonl")) == 500 and len(rg.load("phish.jsonl")) == 500


@pytest.mark.parametrize("name,llm", [("no-model", None), ("realistic-model", rg.realistic_model_stub)])
def test_golden_gate(name, llm):
    s = _run(llm)
    assert s["fpr"] < rg.FPR_LIMIT, s
    assert s["false_positives"] == 0, s["fp_ids"]
    assert s["recall_flagged"] >= rg.MIN_RECALL, s
    assert s["benign_tier1_fast_pass"] >= 300  # reputable + gov/edu + same-site logins skip the model


def test_hallucinating_model_cannot_convict_any_benign_sample():
    """Adversarial model that says 'malicious' for everything. Reputable pages are shielded by Tier 1; unknown
    pages with no physical evidence are downgraded to manual review. Zero may be convicted."""
    res = asyncio.run(rg.evaluate(rg.load("benign.jsonl"), rg.adversarial_model_stub))
    assert [r for r in res if r["verdict"] == "malicious"] == []
    assert all(r["verdict"] == "benign" for r in res if r["category"] != "unknown_clean")
