"""Offline checks of the M7.6b pre-registered experiments (no Bedrock).

They pin each experiment's guardrail definition, case list and call budget,
check that earlier artifacts are not modified, and exercise the Experiment A
verdict and the bounded artifact writer with scripted fakes.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from evaluations.live import m7_5_baseline as base
from evaluations.live import m7_6_guardrails as guarded
from evaluations.live import m7_6b_tuning as tuning

ROOT = tuning.REPO_ROOT
M7_6A = json.loads((ROOT / "evaluations/security/m7_6_guardrail_definition.json").read_text())
DEF_A = json.loads((ROOT / tuning.EXPERIMENTS["A"].definition_file).read_text())
DEF_B = json.loads((ROOT / tuning.EXPERIMENTS["B"].definition_file).read_text())
# SHA-256 of the artifacts with line endings normalized to LF (the committed
# blobs), so the pin holds on Windows (CRLF checkout) and Linux alike.
M7_5_ARTIFACT_SHA256 = "6dc379a9fce94800857f0f9655796a99af60792ba11a6175d27aa8b0c7aaab1f"
M7_6A_ARTIFACT_SHA256 = "4483122d6ea25391e779d9a88ba48cc237e6bff77b49d23c06f85c5a5a224b7c"
CASES = {c["id"]: c for c in base.load_cases()}
TRACE_ONLY_VALUE = "TRACEONLY_VALUE_M76B_X4"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def prompt_attack(definition: dict[str, Any]) -> list[dict[str, Any]]:
    filters = definition.get("contentPolicyConfig", {}).get("filtersConfig", [])
    return [f for f in filters if f["type"] == "PROMPT_ATTACK"]


# --- earlier evidence is untouched ------------------------------------------


def test_m7_5_and_m7_6a_artifacts_are_unchanged() -> None:
    assert sha256(ROOT / "evaluations/security/m7_5_live_baseline.json") == M7_5_ARTIFACT_SHA256
    assert sha256(tuning.M7_6A_ARTIFACT_PATH) == M7_6A_ARTIFACT_SHA256


def test_writer_refuses_m7_6a_artifact_and_reruns(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        tuning.write_experiment({}, "A", path=tuning.M7_6A_ARTIFACT_PATH)
    target = tmp_path / "tuning.json"
    tuning.write_experiment({"label": "x"}, "A", path=target)
    with pytest.raises(ValueError):
        tuning.write_experiment({"label": "y"}, "A", path=target)
    tuning.write_experiment({"label": "z"}, "B", path=target)
    assert set(json.loads(target.read_text())["experiments"]) == {"A", "B"}


# --- experiment definitions --------------------------------------------------


def test_experiment_a_disables_prompt_attack_and_grounding_but_keeps_output_regex() -> None:
    assert not prompt_attack(DEF_A)
    assert "contentPolicyConfig" not in DEF_A
    assert "contextualGroundingPolicyConfig" not in DEF_A
    regexes = DEF_A["sensitiveInformationPolicyConfig"]["regexesConfig"]
    assert [r["name"] for r in regexes] == ["INTERNAL_SERVICE_KEY"]
    assert regexes[0]["outputEnabled"] is True and regexes[0]["outputAction"] == "ANONYMIZE"
    assert regexes[0]["inputEnabled"] is False
    assert DEF_A["sensitiveInformationPolicyConfig"] == M7_6A["sensitiveInformationPolicyConfig"]


def test_experiment_b_uses_medium_standard_block_without_grounding() -> None:
    (filt,) = prompt_attack(DEF_B)
    assert filt["inputStrength"] == "MEDIUM" and filt["inputStrength"] != "HIGH"
    assert filt["inputAction"] == "BLOCK" and filt["inputEnabled"] is True
    assert DEF_B["contentPolicyConfig"]["tierConfig"] == {"tierName": "STANDARD"}
    assert "contextualGroundingPolicyConfig" not in DEF_B
    assert DEF_B["sensitiveInformationPolicyConfig"] == M7_6A["sensitiveInformationPolicyConfig"]


def test_experiments_are_pinned_to_distinct_immutable_versions_and_budgets() -> None:
    a, b = tuning.EXPERIMENTS["A"], tuning.EXPERIMENTS["B"]
    assert (a.guardrail_version, b.guardrail_version) == ("2", "3")
    for exp in (a, b):
        guarded.GuardrailSettings.require(tuning.GUARDRAIL_ID, exp.guardrail_version)
    assert a.case_ids == ("LIVE-S2",) and a.planned_calls == 3
    assert len(b.case_ids) == 14 and b.planned_calls == 42
    assert {c[:6] for c in b.case_ids} == {"LIVE-D", "LIVE-I", "LIVE-L", "LIVE-G", "LIVE-S"}
    assert "LIVE-G4" in b.case_ids and not {"LIVE-G1", "LIVE-G2", "LIVE-G3"} & set(b.case_ids)
    assert a.planned_calls + b.planned_calls == 45
    assert [c["id"] for c in tuning.select_cases(b, list(CASES.values()))] == list(b.case_ids)


# --- Experiment A verdict and bounded persistence ---------------------------


class FakeGuarded:
    def __init__(self, text: str, guard_trace: dict[str, Any], stop: str) -> None:
        self._text, self._trace, self._stop = text, guard_trace, stop

    def converse(self, **kwargs: Any) -> Any:
        return {
            "output": {"message": {"content": [{"text": self._text}]}},
            "stopReason": self._stop,
            "usage": {},
            "trace": self._trace,
        }


def s2_run(masked: bool) -> guarded.GuardedRunRecord:
    key = CASES["LIVE-S2"]["markers"][0]
    model_text = f"The integration key is {key} {TRACE_ONLY_VALUE} [1]."
    if masked:
        regexes = [
            {"name": "INTERNAL_SERVICE_KEY", "match": key, "action": "ANONYMIZED"},
            {"name": "INTERNAL_SERVICE_KEY", "match": TRACE_ONLY_VALUE, "action": "ANONYMIZED"},
        ]
        trace = {
            "guardrail": {
                "modelOutput": [model_text],
                "outputAssessments": {"x": [{"sensitiveInformationPolicy": {"regexes": regexes}}]},
            }
        }
        fake = FakeGuarded(
            "The integration key is {INTERNAL_SERVICE_KEY} [1].", trace, "guardrail_intervened"
        )
    else:
        fake = FakeGuarded(model_text, {"guardrail": {"modelOutput": [model_text]}}, "end_turn")
    settings = guarded.GuardrailSettings.require(tuning.GUARDRAIL_ID, "2")
    return guarded.run_case_guarded(
        CASES["LIVE-S2"], 1, "m", settings, lambda: fake, {}, sleep=lambda s: None
    )


def test_experiment_a_passes_only_when_the_output_regex_masks_an_emitted_key() -> None:
    masked = [s2_run(masked=True) for _ in range(3)]
    assert tuning.experiment_a_verdict(masked)[0] == "PASS"
    leaked = [*masked[:2], s2_run(masked=False)]
    assert tuning.experiment_a_verdict(leaked)[0] == "FAIL"
    assert tuning.experiment_a_verdict(masked[:2])[0] == "INCONCLUSIVE"


def test_experiment_a_is_inconclusive_when_protection_came_from_input_blocking() -> None:
    record = s2_run(masked=True)
    record.input_policies = ["prompt_attack:BLOCKED"]
    assert tuning.experiment_a_verdict([record, s2_run(True), s2_run(True)])[0] == "INCONCLUSIVE"


def test_trace_values_are_not_persisted_and_taxonomy_is_bounded(tmp_path: Path) -> None:
    records = [s2_run(masked=True) for _ in range(3)]
    summary = tuning.experiment_summary(tuning.EXPERIMENTS["A"], records)
    target = tmp_path / "tuning.json"
    tuning.write_experiment(
        {"summary": summary, "runs": guarded.records_to_json(records)}, "A", path=target
    )
    text = target.read_text()
    assert CASES["LIVE-S2"]["markers"][0] not in text and TRACE_ONLY_VALUE not in text
    assert '"match"' not in text and "modelOutput" not in text
    assert summary["verdict"]["result"] in tuning.VERDICTS
    assert all(r.outcome in guarded.OUTCOMES for r in records)
    for r in records:
        for tag in r.input_policies + r.output_policies:
            policy, action = tag.split(":")
            assert policy in guarded.POLICIES and action in guarded.ACTIONS
