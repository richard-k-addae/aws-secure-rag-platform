"""Run the offline evaluation suites and emit a scorecard from real results.

The scorecard reports only executed tests - no projected scores. Live
model-graded metrics (groundedness scores, injection block rates) are added
when the ephemeral AWS deployment exists (Milestone 5).

Results are broken out per control category. A category that reports zero
executed tests fails the gate, so a suite cannot silently disappear and
still show green.

Strict expected failures (known, unfixed gaps) are counted separately from
passes and never as evidence that a control works. An unexpected pass of a
strict xfail is a failure: the case must be promoted deliberately.
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - parses our own junit output
from dataclasses import dataclass, field
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
JUNIT_PATH = REPO_ROOT / "eval-results.xml"
ADVERSARIAL_CASES_PATH = REPO_ROOT / "evaluations" / "security" / "adversarial_cases.json"
ADVERSARIAL_MODULE = "test_adversarial_offline"
ADVERSARIAL_CASE_NAME = re.compile(r"^test_adversarial_case\[(?P<id>[^\]]+)\]$")
ADVERSARIAL_CATEGORY_LABELS: dict[str, str] = {
    "direct_injection": "Direct injection",
    "indirect_injection": "Indirect injection",
    "output_integrity": "Output integrity",
    "authorization_integrity": "Authorization / integrity",
    "no_tools": "No-tools",
}

# Maps the test module that owns a control to its scorecard category. Keys are
# matched against the junit "classname" attribute, which pytest renders as the
# dotted module path (e.g. evaluations.tests.test_groundedness).
#
# The sensitive-data row is labelled "library" deliberately: that suite
# exercises app.core.sensitive_data in isolation against request-side cases.
# Output enforcement (M7.3) is scored by the adversarial OUT-02 case instead.
CATEGORY_BY_MODULE: dict[str, str] = {
    "test_groundedness": "Refusal / groundedness",
    "test_prompt_injection": "Prompt injection",
    "test_response_quality": "Citation integrity",
    "test_sensitive_data": "Sensitive-data detection (library)",
    ADVERSARIAL_MODULE: "Adversarial (offline)",
}

UNCATEGORIZED = "Uncategorized"

PASS, FAIL, XFAIL, XPASS, SKIP = "pass", "fail", "xfail", "xpass", "skip"


def outcome(case: ET.Element) -> str:
    """Classify a junit testcase, keeping strict xfail/xpass distinct from pass/skip."""
    for tag in ("failure", "error"):
        node = case.find(tag)
        if node is not None:
            return XPASS if "XPASS(strict)" in node.get("message", "") else FAIL
    skipped = case.find("skipped")
    if skipped is not None:
        return XFAIL if skipped.get("type") == "pytest.xfail" else SKIP
    return PASS


@dataclass
class CategoryResult:
    """Executed-test counts for one control category."""

    total: int = 0
    failures: int = 0
    skipped: int = 0
    xfailed: int = 0
    failed_ids: list[str] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return self.total - self.failures - self.skipped - self.xfailed

    @property
    def executed(self) -> int:
        """Tests that actually ran. Skips do not count; strict xfails ran and failed."""
        return self.total - self.skipped

    @property
    def status(self) -> str:
        if self.failures:
            return "FAIL"
        if self.executed == 0:
            return "FAIL"
        return "PASS"


def categorize(classname: str) -> str:
    for module, category in CATEGORY_BY_MODULE.items():
        if module in classname:
            return category
    return UNCATEGORIZED


def collect_categories(suite: ET.Element) -> dict[str, CategoryResult]:
    """Bucket junit testcases into control categories."""
    results: dict[str, CategoryResult] = {
        category: CategoryResult() for category in CATEGORY_BY_MODULE.values()
    }
    for case in suite.iter("testcase"):
        category = categorize(case.get("classname", ""))
        result = results.setdefault(category, CategoryResult())
        result.total += 1
        kind = outcome(case)
        if kind in (FAIL, XPASS):
            result.failures += 1
            result.failed_ids.append(case.get("name", "?"))
        elif kind == XFAIL:
            result.xfailed += 1
        elif kind == SKIP:
            result.skipped += 1
    return results


@dataclass
class AdversarialRow:
    """Per-category outcome counts for the adversarial corpus."""

    cases: int = 0
    enforced_passes: int = 0
    characterization_passes: int = 0
    strict_xfails: int = 0
    unexpected_failures: int = 0
    unexpected_passes: int = 0
    not_executed: int = 0
    problem_ids: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.unexpected_failures or self.unexpected_passes or self.not_executed)


def adversarial_scorecard(suite: ET.Element) -> tuple[list[str], bool]:
    """Score every corpus case by its declared control_status.

    A corpus case with no executed testcase counts as not executed and fails
    the gate, so corpus size and executed count must match.
    """
    corpus = json.loads(ADVERSARIAL_CASES_PATH.read_text(encoding="utf-8"))
    status_by_id = {case["id"]: case["control_status"] for case in corpus}
    category_by_id = {case["id"]: case["category"] for case in corpus}
    outcomes: dict[str, str] = {}
    for case in suite.iter("testcase"):
        if ADVERSARIAL_MODULE not in case.get("classname", ""):
            continue
        match = ADVERSARIAL_CASE_NAME.match(case.get("name", ""))
        if match:
            outcomes[match.group("id")] = outcome(case)

    rows = {label: AdversarialRow() for label in ADVERSARIAL_CATEGORY_LABELS.values()}
    for case_id, status in status_by_id.items():
        row = rows.setdefault(
            ADVERSARIAL_CATEGORY_LABELS.get(category_by_id[case_id], UNCATEGORIZED),
            AdversarialRow(),
        )
        row.cases += 1
        kind = outcomes.get(case_id)
        if kind is None or kind == SKIP:
            row.not_executed += 1
            row.problem_ids.append(f"{case_id} (not executed)")
        elif kind == PASS and status == "enforced":
            row.enforced_passes += 1
        elif kind == PASS and status == "characterization":
            row.characterization_passes += 1
        elif kind == XFAIL and status == "not_implemented":
            row.strict_xfails += 1
        elif kind == XPASS or (kind == PASS and status == "not_implemented"):
            row.unexpected_passes += 1
            row.problem_ids.append(f"{case_id} (unexpected pass)")
        else:
            row.unexpected_failures += 1
            row.problem_ids.append(f"{case_id} ({kind}, declared {status})")

    total = AdversarialRow()
    for row in rows.values():
        total.cases += row.cases
        total.enforced_passes += row.enforced_passes
        total.characterization_passes += row.characterization_passes
        total.strict_xfails += row.strict_xfails
        total.unexpected_failures += row.unexpected_failures
        total.unexpected_passes += row.unexpected_passes
        total.not_executed += row.not_executed
        total.problem_ids += row.problem_ids

    def line(label: str, r: AdversarialRow) -> str:
        return (
            f"| {label} | {r.cases} | {r.enforced_passes} | {r.characterization_passes} "
            f"| {r.strict_xfails} | {r.unexpected_failures} | {r.unexpected_passes} "
            f"| {r.not_executed} | {'PASS' if r.clean else 'FAIL'} |"
        )

    lines = [
        "### Adversarial (offline) scorecard",
        "",
        "Strict expected failures are known, unfixed gaps. They are not passes.",
        "",
        "| Category | Cases | Enforced pass | Characterization pass | Strict xfail "
        "| Unexpected fail | Unexpected pass | Not executed | Status |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    lines += [line(label, row) for label, row in rows.items()]
    lines.append(line("**Total**", total))
    if total.problem_ids:
        lines += ["", "Adversarial problems: " + ", ".join(total.problem_ids)]
    return lines, total.clean


def build_scorecard(junit: Path) -> tuple[str, bool]:
    """Render the scorecard. Returns the markdown and whether every gate held."""
    suite = ET.parse(junit).getroot().find("testsuite")  # noqa: S314 - trusted local file
    if suite is None:
        raise RuntimeError("junit report missing testsuite element")
    categories = collect_categories(suite)
    total = sum(result.total for result in categories.values())
    failures = sum(result.failures for result in categories.values())
    skipped = sum(result.skipped for result in categories.values())
    xfailed = sum(result.xfailed for result in categories.values())
    passed = total - failures - skipped - xfailed
    status = "PASS" if failures == 0 else "FAIL"

    # A fully skipped category proves nothing, so it counts as unexecuted and
    # fails the gate exactly as a missing suite would.
    unexecuted = [
        name
        for name, result in categories.items()
        if result.executed == 0
    ]
    adversarial_lines, adversarial_clean = adversarial_scorecard(suite)
    all_green = failures == 0 and not unexecuted and adversarial_clean

    lines = [
        "## AI Evaluation Gate (offline)",
        "",
        "| Metric | Value | Status |",
        "|---|---|---|",
        f"| Evaluation tests passed | {passed}/{total} | {status} |",
        f"| Failures (incl. strict XPASS) | {failures} | {'PASS' if failures == 0 else 'FAIL'} |",
        f"| Strict expected failures (known gaps) | {xfailed} | info |",
        f"| Skipped | {skipped} | info |",
        "",
        "### Per-category scorecard",
        "",
        "| Category | Passed | Failed | Strict xfail | Skipped | Status |",
        "|---|---|---|---|---|---|",
    ]
    for name in sorted(categories):
        result = categories[name]
        lines.append(
            f"| {name} | {result.passed}/{result.total} | {result.failures} "
            f"| {result.xfailed} | {result.skipped} | {result.status} |"
        )
    lines += ["", *adversarial_lines]

    failed_detail = [
        f"- {name}: {', '.join(result.failed_ids)}"
        for name, result in sorted(categories.items())
        if result.failed_ids
    ]
    if failed_detail:
        lines += ["", "Failed checks:", *failed_detail]

    if unexecuted:
        lines += [
            "",
            "Gate failed: no executed (non-skipped) tests for "
            f"{', '.join(sorted(unexecuted))}.",
        ]

    lines += [
        "",
        "### Scope of these gates",
        "",
        "Offline gates are deterministic behavioral checks, not scores:",
        "no-context refusal, injection confinement, citation integrity,",
        "sensitive-data detection, and the adversarial corpus.",
        "",
        "Adversarial results are STRUCTURAL: they show what the platform sends to",
        "the model and returns to the caller. They do not show that a model",
        "resists jailbreaks or ignores injected text; that is the live evaluation.",
        "",
        "Sensitive-data library results cover DETECTION of request-side cases.",
        "Model-output enforcement (withhold credentials/identifiers, mask",
        "emails) exists for /v1/query answers and is scored by adversarial",
        "case OUT-02. Request input is NOT checked at runtime.",
        "",
        "Latency, live Bedrock behavior and model-graded metrics are not verified",
        "by this run and remain informational until Milestone 5.",
    ]
    return "\n".join(lines), all_green


def main() -> int:
    sys.path.insert(0, str(REPO_ROOT))
    code = pytest.main([str(REPO_ROOT / "evaluations" / "tests"), "-q", f"--junitxml={JUNIT_PATH}"])
    scorecard, all_green = build_scorecard(JUNIT_PATH)
    print(scorecard)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(scorecard + "\n")
    if int(code) != 0:
        return int(code)
    return 0 if all_green else 1


if __name__ == "__main__":
    sys.exit(main())
