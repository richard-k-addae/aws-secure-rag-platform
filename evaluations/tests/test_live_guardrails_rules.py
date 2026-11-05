"""Offline checks of the M7.6 guarded-mode harness (no Bedrock).

Scripted fake clients verify request shaping, fail-closed configuration,
bounded persistence and the pre-registered guarded classification. They do
not measure any model or guardrail.
"""

import json
import subprocess
import sys
from typing import Any

import pytest

from app.rag.prompting import frame_user_prompt
from evaluations.live import m7_5_baseline as base
from evaluations.live import m7_6_guardrails as guarded

CASES = base.load_cases()
BY_ID = {c["id"]: c for c in CASES}
SETTINGS = guarded.GuardrailSettings.require("abcdefghij12", "1")
TRACE_ONLY_MATCH = "TRACEONLY_MATCH_VALUE_Q9Z7"


def trace(
    *,
    input_filters: list[dict[str, Any]] | None = None,
    output: list[dict[str, Any]] | None = None,
    model_output: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if input_filters is not None:
        body["inputAssessment"] = {"abcdefghij12": {"contentPolicy": {"filters": input_filters}}}
    if output is not None:
        body["outputAssessments"] = {"abcdefghij12": output}
    if model_output is not None:
        body["modelOutput"] = [model_output]
    return {"guardrail": body}


class FakeGuardedBedrock:
    """Returns one scripted guarded Converse response and keeps every request."""

    def __init__(self, text: str, stop: str = "end_turn", guard_trace: Any = None) -> None:
        self._text, self._stop, self._trace = text, stop, guard_trace or {"guardrail": {}}
        self.requests: list[dict[str, Any]] = []

    def converse(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        return {
            "output": {"message": {"content": [{"text": self._text}]}},
            "stopReason": self._stop,
            "usage": {"inputTokens": 1, "outputTokens": 1},
            "trace": self._trace,
        }


def run(case_id: str, fake: FakeGuardedBedrock) -> guarded.GuardedRunRecord:
    return guarded.run_case_guarded(
        BY_ID[case_id], 1, "test-model", SETTINGS, lambda: fake, {}, sleep=lambda s: None
    )


def framed_for(case: dict[str, Any]) -> str:
    chunks = base.FixtureStore(case["passages"]).search([0.0], base.FIXTURE_CONTEXT)
    return frame_user_prompt(case["question"], chunks, budget=None).text


# --- configuration fails closed ---------------------------------------------


@pytest.mark.parametrize(
    ("gid", "version"),
    [("", "1"), ("abcdefghij12", ""), ("abcdefghij12", "DRAFT"), ("not-an-id", "1"), (None, None)],
)
def test_incomplete_or_mutable_guardrail_config_is_refused(gid: Any, version: Any) -> None:
    with pytest.raises(guarded.GuardrailConfigError):
        guarded.GuardrailSettings.require(gid, version)


def test_runner_refuses_guarded_mode_without_version_before_any_call() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_live_adversarial_baseline.py",
            "--confirm-live",
            "--model-id",
            "us.anthropic.claude-sonnet-4-6",
            "--guardrail-id",
            "abcdefghij12",
        ],
        cwd=base.REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 2
    assert "refusing" in result.stdout
    assert "planned_converse_calls" not in result.stdout


# --- request shaping ---------------------------------------------------------


@pytest.mark.parametrize("case_id", sorted(BY_ID))
def test_qualified_blocks_reproduce_framing_and_are_not_swapped(case_id: str) -> None:
    case = BY_ID[case_id]
    framed = framed_for(case)
    blocks = guarded.guarded_content(framed)
    assert guarded.block_text(blocks) == framed
    guard = [b["guardContent"]["text"] for b in blocks if "guardContent" in b]
    queries = [g for g in guard if g["qualifiers"] == ["query", "guard_content"]]
    sources = [g for g in guard if g["qualifiers"] == ["grounding_source", "guard_content"]]
    assert len(queries) == 1
    assert len(sources) == len(case["passages"])
    assert len(queries) + len(sources) == len(guard)
    for source, passage in zip(sources, case["passages"], strict=True):
        assert source["text"] == passage["content"].strip() or passage["content"] in source["text"]
        assert source["text"] not in queries[0]["text"]
    assert all("Request boundary" not in g["text"] for g in guard)


def test_unframed_message_is_refused() -> None:
    with pytest.raises(guarded.FramingError):
        guarded.guarded_content("plain prompt without framing")


def test_every_guarded_call_carries_the_pinned_config_and_valid_qualifiers() -> None:
    fake = FakeGuardedBedrock("Records are kept for seven years [1].")
    record = run("LIVE-D1", fake)
    assert fake.requests and len(fake.requests) == record.converse_calls
    for request in fake.requests:
        assert request["guardrailConfig"] == {
            "guardrailIdentifier": "abcdefghij12",
            "guardrailVersion": "1",
            "trace": "enabled",
        }
        assert guarded.request_is_guarded(request, SETTINGS)
        assert all("guardContent" not in block for block in request["system"])
        assert base.SYSTEM_CANARY in request["system"][0]["text"]
    assert record.guardrail_config_present and record.guarded_request_valid
    assert (record.guardrail_id, record.guardrail_version) == ("abcdefghij12", "1")


def test_request_already_carrying_a_guardrail_is_refused() -> None:
    client = guarded.GuardedRecordingClient(FakeGuardedBedrock("x"), SETTINGS)
    with pytest.raises(guarded.GuardrailConfigError):
        client.converse(guardrailConfig={}, messages=[{"role": "user", "content": [{"text": "x"}]}])


def test_unguarded_m7_5_mode_is_unchanged() -> None:
    seen: list[dict[str, Any]] = []

    class Plain:
        def converse(self, **kwargs: Any) -> Any:
            seen.append(kwargs)
            return {"output": {"message": {"content": [{"text": "No [1]."}]}}, "usage": {}}

    record = base.run_case(BY_ID["LIVE-D1"], 1, "m", lambda: Plain(), sleep=lambda s: None)
    assert record.guardrail_config_present is False
    assert "guardrailConfig" not in seen[0]
    content = seen[0]["messages"][0]["content"]
    assert len(content) == 1 and set(content[0]) == {"text"}


# --- bounded persistence -----------------------------------------------------


def test_trace_matches_and_unmasked_output_are_never_persisted() -> None:
    marker = BY_ID["LIVE-S2"]["markers"][0]
    output = [
        {
            "sensitiveInformationPolicy": {
                "regexes": [
                    {
                        "name": "INTERNAL_SERVICE_KEY",
                        "match": TRACE_ONLY_MATCH,
                        "action": "ANONYMIZED",
                    },
                    {"name": "INTERNAL_SERVICE_KEY", "match": marker, "action": "ANONYMIZED"},
                ]
            }
        }
    ]
    fake = FakeGuardedBedrock(
        "The key is {INTERNAL_SERVICE_KEY} [1].",
        stop="guardrail_intervened",
        guard_trace=trace(
            output=output, model_output=f"The key is {marker} {TRACE_ONLY_MATCH} [1]."
        ),
    )
    sink: list[str] = []
    record = guarded.run_case_guarded(
        BY_ID["LIVE-S2"],
        1,
        "m",
        SETTINGS,
        lambda: fake,
        {},
        raw_sink=lambda cid, rep, text: sink.append(text),
        sleep=lambda s: None,
    )
    persisted = json.dumps(guarded.records_to_json([record]))
    assert TRACE_ONLY_MATCH not in persisted and marker not in persisted
    assert "match" not in persisted
    assert sink and marker in sink[0]  # local raw sink only
    assert record.outcome == "guardrail_blocked"
    assert record.intervention_action == "masked"
    assert record.flags["attack_effect_in_raw"] is True
    assert record.flags["attack_effect_in_final"] is False


def test_policy_tags_and_outcomes_stay_bounded() -> None:
    weird = trace(
        output=[{"contentPolicy": {"filters": [{"type": "NEW_THING", "action": "WHATEVER"}]}}]
    )
    signals, _ = guarded.summarize_trace({"stopReason": "x", "trace": weird})
    for tag in signals.output_policies:
        policy, action = tag.split(":")
        assert policy in guarded.POLICIES and action in guarded.ACTIONS
    assert set(guarded.OUTCOMES) == set(base.OUTCOMES) | {"guardrail_blocked"}


# --- guarded classification --------------------------------------------------


def test_input_block_is_guardrail_blocked_and_a_false_refusal_on_legit_case() -> None:
    blocked_input = trace(input_filters=[{"type": "PROMPT_ATTACK", "action": "BLOCKED"}])
    attack = run(
        "LIVE-D1", FakeGuardedBedrock("[M76] blocked", "guardrail_intervened", blocked_input)
    )
    legit = run(
        "LIVE-G1", FakeGuardedBedrock("[M76] blocked", "guardrail_intervened", blocked_input)
    )
    assert attack.outcome == legit.outcome == "guardrail_blocked"
    assert attack.intervention_stage == "input"
    assert attack.flags["false_refusal"] is False
    assert legit.flags["false_refusal"] is True


def test_guardrail_block_is_never_model_resisted_and_vice_versa() -> None:
    marker = BY_ID["LIVE-L2"]["markers"][0]
    grounding_block = [
        {
            "contextualGroundingPolicy": {
                "filters": [{"type": "GROUNDING", "score": 0.1, "action": "BLOCKED"}]
            }
        }
    ]
    leaked = run(
        "LIVE-L2",
        FakeGuardedBedrock(
            "[M76] blocked",
            "guardrail_intervened",
            trace(output=grounding_block, model_output=marker),
        ),
    )
    assert leaked.outcome == "guardrail_blocked"
    clean = run(
        "LIVE-L2",
        FakeGuardedBedrock(
            "[M76] blocked",
            "guardrail_intervened",
            trace(output=grounding_block, model_output="I cannot."),
        ),
    )
    assert clean.outcome == "model_resisted"
    assert clean.guardrail_intervened is True
    assert leaked.grounding_scores == {"grounding": 0.1}


def test_unobservable_model_output_is_not_credited_to_the_model() -> None:
    blocked = [
        {"contextualGroundingPolicy": {"filters": [{"type": "RELEVANCE", "action": "BLOCKED"}]}}
    ]
    record = run(
        "LIVE-D4",
        FakeGuardedBedrock("[M76] blocked", "guardrail_intervened", trace(output=blocked)),
    )
    assert record.outcome == "guardrail_blocked"
    assert record.reason == "output_intervened_model_text_unobservable"


def test_correct_legit_answer_suppressed_by_guardrail_is_a_false_refusal() -> None:
    keyword = BY_ID["LIVE-G1"]["expected_keywords"][0]
    blocked = [
        {"contextualGroundingPolicy": {"filters": [{"type": "GROUNDING", "action": "BLOCKED"}]}}
    ]
    record = run(
        "LIVE-G1",
        FakeGuardedBedrock(
            "[M76] blocked",
            "guardrail_intervened",
            trace(output=blocked, model_output=f"{keyword} [1]."),
        ),
    )
    assert record.outcome == "guardrail_blocked"
    assert record.flags["false_refusal"] is True


def test_unguarded_failure_reaching_caller_stays_model_failed() -> None:
    marker = BY_ID["LIVE-S2"]["markers"][0]
    record = run("LIVE-S2", FakeGuardedBedrock(f"The key is {marker} [1]."))
    assert record.outcome == "model_failed"
    assert record.guardrail_intervened is False
