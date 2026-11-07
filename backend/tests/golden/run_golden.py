#!/usr/bin/env python3
"""
run_golden.py - End-to-end golden regression runner.

Modes
  (default) offline : replays the 500 benign + 500 phishing telemetry fixtures through the real
                      decision pipeline (reputation gate -> heuristics -> Tier 2 w/ pluggable model).
  --live FILE       : FILE is `label,url` per line (label = benign|phish). Every URL is detonated in the
                      containerised Playwright sandbox (requires Docker + phishchips-sandbox image), then
                      analysed with the configured inference engine.

Gates (exit code 1 on failure)
  * false-positive rate (benign classified `malicious`) must be < 0.1%  (i.e. 0 of 500)
  * phishing recall (flagged as suspicious|malicious) must be >= MIN_RECALL (default 0.95)
"""

import argparse
import asyncio
import json
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

import analyzer  # noqa: E402

FPR_LIMIT = 0.001
MIN_RECALL = 0.95

LLMStub = Callable[[List[Dict[str, Any]], float], Awaitable[str]]


def load(name: str) -> List[Dict[str, Any]]:
    with open(HERE / name, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


async def realistic_model_stub(messages, timeout) -> str:
    """Stand-in for a competent model: trusts physical evidence, otherwise benign."""
    payload = json.loads(messages[-1]["content"].split("\n", 1)[1] if isinstance(messages[-1]["content"], str)
                         else messages[-1]["content"][0]["text"].split("\n", 1)[1])
    hard = payload["heuristic_signals"]["hard"]
    if hard:
        return json.dumps({"verdict": "malicious", "confidence": 0.93, "indicators": hard,
                           "evidence_chain": [f"Physical anomaly? -> {h}" for h in hard]})
    return json.dumps({"verdict": "benign", "confidence": 0.9, "indicators": [],
                       "evidence_chain": ["Credential theft or off-site exfiltration observed? -> no"]})


async def adversarial_model_stub(messages, timeout) -> str:
    """Worst case: a hallucinating model that calls EVERYTHING malicious."""
    return json.dumps({"verdict": "malicious", "confidence": 0.98, "indicators": ["model says so"],
                       "evidence_chain": ["Looks like phishing -> vibes"]})


async def evaluate(rows: List[Dict[str, Any]], llm: Optional[LLMStub]) -> List[Dict[str, Any]]:
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        for row in rows:
            res = await analyzer.analyze_threat(
                json.loads(json.dumps(row["sample"])), Path(tmp), deadline=time.monotonic() + 20, llm_call=llm
            )
            out.append({"id": row["id"], "category": row["category"], "verdict": res["verdict_class"], "tier": res["tier"]})
    return out


def summarize(benign_res, phish_res) -> Dict[str, Any]:
    fp = [r for r in benign_res if r["verdict"] == "malicious"]
    review = [r for r in benign_res if r["verdict"] in ("suspicious", "indeterminate")]
    flagged = [r for r in phish_res if r["verdict"] in ("suspicious", "malicious")]
    mal = [r for r in phish_res if r["verdict"] == "malicious"]
    return {
        "benign_total": len(benign_res), "false_positives": len(fp), "fpr": len(fp) / max(1, len(benign_res)),
        "benign_manual_review": len(review), "benign_tier1_fast_pass": sum(1 for r in benign_res if r["tier"] == "tier1" and r["verdict"] == "benign"),
        "phish_total": len(phish_res), "recall_flagged": len(flagged) / max(1, len(phish_res)),
        "recall_malicious": len(mal) / max(1, len(phish_res)),
        "fp_ids": [r["id"] for r in fp][:10],
        "missed_by_category": dict(Counter(r["category"] for r in phish_res if r["verdict"] == "benign")),
    }


async def _no_probe(url, budget=3.0):
    return {"apex": "", "resolves": None, "tls": None, "age_days": None}


async def run_offline(llm: Optional[LLMStub]) -> Dict[str, Any]:
    analyzer.corroborate_apex = _no_probe  # fixtures use fabricated hosts: never probe DNS/TLS/RDAP
    benign = await evaluate(load("benign.jsonl"), llm)
    phish = await evaluate(load("phish.jsonl"), llm)
    return summarize(benign, phish)


async def run_live(path: str) -> Dict[str, Any]:  # pragma: no cover - needs Docker
    import scanner

    benign_res, phish_res = [], []
    for i, line in enumerate(Path(path).read_text().splitlines()):
        if not line.strip() or line.startswith("#"):
            continue
        label, url = [x.strip() for x in line.split(",", 1)]
        job_id = f"golden{i:04d}"
        telemetry = await scanner.run_docker_sandbox(job_id, url)
        res = await analyzer.analyze_threat(telemetry, scanner.EVIDENCE_DIR / job_id)
        rec = {"id": url, "category": label, "verdict": res["verdict_class"], "tier": res["tier"]}
        (benign_res if label == "benign" else phish_res).append(rec)
    return summarize(benign_res, phish_res)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", help="label,url CSV to detonate in the Docker sandbox")
    ap.add_argument("--model", choices=["none", "realistic", "adversarial"], default="realistic",
                    help="offline Tier-2 model stub (ignored for --live)")
    args = ap.parse_args()
    import os
    if args.live:
        summary = asyncio.run(run_live(args.live))
    else:
        os.environ["VULTR_INFERENCE_API_KEY"] = ""
        llm = {"none": None, "realistic": realistic_model_stub, "adversarial": adversarial_model_stub}[args.model]
        summary = asyncio.run(run_offline(llm))
    print(json.dumps(summary, indent=2))
    ok = summary["fpr"] < FPR_LIMIT and summary["recall_flagged"] >= MIN_RECALL
    print("PASS" if ok else "FAIL", f"(FPR {summary['fpr']:.4%} < {FPR_LIMIT:.2%}, recall {summary['recall_flagged']:.1%} >= {MIN_RECALL:.0%})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
