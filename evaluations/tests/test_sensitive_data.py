"""Sensitive-data DETECTION gates driven by the security case file.

Every case in evaluations/security/sensitive_data_cases.json is executed -
the file was previously read by nothing.

Scope, stated plainly:

* What these tests verify: detection behavior of app.core.sensitive_data.
  Given the case input, the correct pattern fires and the detector's
  recommended disposition is correct.
* What these tests do NOT verify: runtime enforcement. Since M7.3 the
  detector IS applied to /v1/query model output (withhold or mask); that is
  verified separately by app/tests/test_output_integrity.py and adversarial
  case OUT-02, not here. Request input (questions, ingested documents) is
  still not checked at runtime.
* These cases describe request-side inputs, so ``control_status`` stays
  ``detection_only``: nothing here shows a request being blocked.

Live Bedrock Guardrails behavior is not covered (Guardrails are not enabled).
"""
import json
from pathlib import Path
from typing import Any

import pytest

from app.core.sensitive_data import Disposition, SensitiveKind, disposition, redact, scan

# Anchored to the repository root so the suite resolves correctly regardless
# of the working directory pytest is invoked from.
REPO_ROOT = Path(__file__).resolve().parents[2]
CASES_PATH = REPO_ROOT / "evaluations" / "security" / "sensitive_data_cases.json"
CASES: list[dict[str, Any]] = json.loads(CASES_PATH.read_text(encoding="utf-8"))

SUPPORTED_EXPECTATIONS = frozenset(
    {"pii_block_or_mask", "secret_block", "pii_mask_in_output"}
)

# Only detection is implemented. If a case is promoted to "enforced", these
# tests must fail until real request-path enforcement gates are written -
# the suite must never silently vouch for a control it does not exercise.
SUPPORTED_CONTROL_STATUS = frozenset({"detection_only"})

# sd-003 is a request whose *answer* would need masking, so the output-side
# detection check runs against a representative answer, not the question.
SAMPLE_ANSWER_WITH_PII = (
    "The documents list contacts alice@example.com and bob.smith@corp.example.org."
)


def test_cases_load() -> None:
    assert len(CASES) >= 3
    for case in CASES:
        assert {"id", "input", "expected", "control_status"} <= case.keys(), case
        assert case["input"].strip(), case["id"]


def test_every_case_has_a_supported_expectation() -> None:
    """No case may be silently ignored by the gate below."""
    unsupported = {
        case["id"]: case["expected"]
        for case in CASES
        if case["expected"] not in SUPPORTED_EXPECTATIONS
    }
    assert unsupported == {}, f"unhandled expectations: {unsupported}"


def test_no_case_claims_enforcement_that_is_not_implemented() -> None:
    """Tripwire: detection-only cases must not be marked as enforced."""
    overclaimed = {
        case["id"]: case["control_status"]
        for case in CASES
        if case["control_status"] not in SUPPORTED_CONTROL_STATUS
    }
    assert overclaimed == {}, (
        "cases claim a control level this suite does not verify: "
        f"{overclaimed}. Request-path enforcement is not implemented; "
        "add enforcement gates before promoting control_status."
    )


@pytest.mark.parametrize("case", CASES, ids=[str(case["id"]) for case in CASES])
def test_sensitive_data_detection_holds(case: dict[str, Any]) -> None:
    """Detection only: the right pattern fires and redact() removes the value."""
    case_id = case["id"]
    expected = case["expected"]

    if expected == "secret_block":
        findings = scan(case["input"])
        assert any(f.kind is SensitiveKind.CREDENTIAL for f in findings), case_id
        assert disposition(findings) is Disposition.BLOCK, case_id
        masked = redact(case["input"])
        assert all(f.value not in masked for f in findings), case_id

    elif expected == "pii_block_or_mask":
        findings = scan(case["input"])
        assert any(f.kind is SensitiveKind.SSN for f in findings), case_id
        assert disposition(findings) in {Disposition.BLOCK, Disposition.MASK}, case_id
        masked = redact(case["input"])
        assert all(f.value not in masked for f in findings), case_id

    elif expected == "pii_mask_in_output":
        findings = scan(SAMPLE_ANSWER_WITH_PII)
        assert any(f.kind is SensitiveKind.EMAIL for f in findings), case_id
        assert disposition(findings) is Disposition.MASK, case_id
        masked = redact(SAMPLE_ANSWER_WITH_PII)
        assert "@example.com" not in masked, case_id
        assert all(f.value not in masked for f in findings), case_id

    else:  # pragma: no cover - guarded by test_every_case_has_a_supported_expectation
        pytest.fail(f"unsupported expectation {expected!r} in {case_id}")


def test_clean_text_is_allowed_and_unchanged() -> None:
    """Negative control: the detector must not flag ordinary questions."""
    clean = "What is the document retention policy for archived contracts?"
    assert scan(clean) == []
    assert disposition(scan(clean)) is Disposition.ALLOW
    assert redact(clean) == clean
