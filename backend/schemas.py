"""
schemas.py - Enforced structured-output contracts for Phish&Chips inference.

The model may never return free-form text. Anything that does not validate
against ModelVerdict is rejected (counted as a schema violation) and the job
degrades to INDETERMINATE - it never degrades to MALICIOUS.
"""

from __future__ import annotations

import json
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

VerdictClass = Literal["benign", "suspicious", "malicious", "indeterminate"]

# Legacy vocabulary still consumed by the UI / SQLite layer.
LEGACY_VERDICT = {
    "benign": "SAFE",
    "suspicious": "SUSPICIOUS",
    "malicious": "SCAM",
    "indeterminate": "INDETERMINATE",
}


class ModelVerdict(BaseModel):
    """Exact shape the AI model must emit. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    verdict: Literal["benign", "suspicious", "malicious"]
    confidence: float = Field(ge=0.0, le=1.0)
    indicators: List[str] = Field(default_factory=list, max_length=12)
    evidence_chain: List[str] = Field(default_factory=list, max_length=12)
    pretending_to_be: Optional[str] = None
    asks_for: List[str] = Field(default_factory=list, max_length=8)

    @field_validator("verdict", mode="before")
    @classmethod
    def _lower_verdict(cls, v):
        # Casing is the only normalisation allowed; synonyms ("safe", "scam") are rejected.
        return v.strip().lower() if isinstance(v, str) else v

    @model_validator(mode="after")
    def _justification_required(self) -> "ModelVerdict":
        # Every verdict needs an explicit behavioural justification.
        if not self.evidence_chain:
            raise ValueError("evidence_chain must contain at least one behavioural justification")
        if self.verdict in ("suspicious", "malicious") and not self.indicators:
            raise ValueError("suspicious/malicious verdicts require at least one indicator")
        return self


class SchemaViolation(Exception):
    """Raised when raw model output cannot be coerced into ModelVerdict."""


def parse_model_output(raw: str) -> ModelVerdict:
    """Strictly parse + validate raw model text. Raises SchemaViolation."""
    if not raw or not raw.strip():
        raise SchemaViolation("empty model response")
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    if not text.startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise SchemaViolation("no JSON object in model response")
        text = text[start : end + 1]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaViolation(f"invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SchemaViolation("model JSON root must be an object")
    try:
        return ModelVerdict.model_validate(payload)
    except ValidationError as exc:
        raise SchemaViolation(str(exc.errors()[:3])) from exc


MODEL_OUTPUT_SCHEMA_TEXT = (
    "{\n"
    '  "verdict": "benign" | "suspicious" | "malicious",\n'
    '  "confidence": <float 0.0-1.0>,\n'
    '  "indicators": ["<observed anomaly>", ...],      // required (>=1) unless benign\n'
    '  "evidence_chain": ["<claim> -> <observation>", ...],  // required (>=1)\n'
    '  "pretending_to_be": "<brand>" | null,\n'
    '  "asks_for": ["<sensitive field>", ...]\n'
    "}"
)

