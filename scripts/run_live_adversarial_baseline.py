"""M7.5 live adversarial baseline WITHOUT Bedrock Guardrails (non-blocking).

Usage:
  python scripts/run_live_adversarial_baseline.py --plan
  python scripts/run_live_adversarial_baseline.py --confirm-live --model-id <id>

M7.6 guarded mode (same cases, one pinned guardrail version on every call):
  python scripts/run_live_adversarial_baseline.py --confirm-live --model-id <id> \
      --guardrail-id <id> --guardrail-version <n>

Never part of CI: it needs Bedrock, costs money and measures nondeterministic
model behavior. Results are baseline evidence, not a gate.

ID-01 remains unresolved. Caller tenant/role is a test fixture only; these
results make no authentication or authorization claim.
"""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

PLACEHOLDER_MODEL = "anthropic.claude-sonnet-example-model-id"
ARTIFACT = REPO_ROOT / "evaluations" / "security" / "m7_5_live_baseline.json"
GUARDED_ARTIFACT = REPO_ROOT / "evaluations" / "security" / "m7_6_guardrails_baseline.json"
MAX_PLANNED_CALLS = 60


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", action="store_true", help="print the plan; make no calls")
    parser.add_argument("--confirm-live", action="store_true", help="required for live calls")
    parser.add_argument("--model-id", default=os.environ.get("BEDROCK_MODEL_ID", ""))
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--raw-dir", default="", help="local-only dir for raw synthetic output")
    parser.add_argument("--guardrail-id", default="", help="M7.6 guarded mode: guardrail ID")
    parser.add_argument(
        "--guardrail-version", default="", help="M7.6 guarded mode: numeric guardrail version"
    )
    parser.add_argument(
        "--experiment", default="", choices=["", "A", "B"], help="M7.6b pinned experiment"
    )
    args = parser.parse_args()
    if args.experiment:
        return experiment_main(args)
    if args.guardrail_id or args.guardrail_version:
        return guarded_main(args)

    # Pin the run's configuration before any app module reads settings.
    os.environ["BEDROCK_MODEL_ID"] = args.model_id
    os.environ["LOG_FULL_CONTENT"] = "false"
    os.environ.setdefault("LOG_LEVEL", "WARNING")
    for name in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
        os.environ.pop(name, None)

    from evaluations.live import m7_5_baseline as live

    cases = live.load_cases()
    planned = len(cases) * args.repetitions
    print(live.ID01_STATEMENT)
    print(
        f"cases={len(cases)} repetitions={args.repetitions} planned_converse_calls={planned} "
        f"(+ at most {planned * 2} transient retries); embedding/db calls=0 (fixture retrieval)"
    )
    print("guardrails: NONE configured (verified per call)")
    if args.plan:
        return 0
    if planned > MAX_PLANNED_CALLS:
        print(f"refusing: planned calls {planned} exceed cap {MAX_PLANNED_CALLS}")
        return 2
    if not args.confirm_live:
        print("refusing: pass --confirm-live to make live Bedrock calls")
        return 2
    if not args.model_id or args.model_id == PLACEHOLDER_MODEL:
        print("refusing: set --model-id to a real Bedrock model or inference profile")
        return 2

    import boto3

    from app.core.config import get_settings

    settings = get_settings()
    if settings.bedrock_model_id != args.model_id or settings.log_full_content:
        print("refusing: settings did not pick up the pinned configuration")
        return 2
    region = settings.aws_region

    raw_dir = Path(args.raw_dir) if args.raw_dir else None
    if raw_dir is not None:
        if REPO_ROOT in raw_dir.resolve().parents or raw_dir.resolve() == REPO_ROOT:
            print("refusing: --raw-dir must be outside the repository")
            return 2
        raw_dir.mkdir(parents=True, exist_ok=True)

    def raw_sink(case_id: str, repetition: int, text: str) -> None:
        if raw_dir is not None:
            (raw_dir / f"{case_id}-r{repetition}.txt").write_text(text, encoding="utf-8")

    def client() -> object:
        return boto3.client("bedrock-runtime", region_name=region)

    records = []
    for case in cases:
        for repetition in range(1, args.repetitions + 1):
            record = live.run_case(case, repetition, args.model_id, client, raw_sink)
            records.append(record)
            print(f"{record.case_id} r{repetition}: {record.outcome} ({record.reason})")
            if record.guardrail_config_present:
                print("aborting: a guardrail configuration was sent; baseline invalid")
                return 3
            if record.error_type and record.error_type not in live.TRANSIENT_CODES:
                print(f"aborting: non-transient Bedrock error {record.error_type}")
                break
        else:
            continue
        break

    summary = live.summarize(records)
    artifact = {
        "milestone": "M7.5",
        "statement": live.ID01_STATEMENT,
        "guardrails": "none configured; verified per call (guardrail_config_present)",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "generation_model_id": args.model_id,
        "embedding_model_id": "not used: retrieval pinned by fixture store",
        "region": region,
        "system_prompt": "production SYSTEM_PROMPT plus one test-only canary sentence",
        "cases_file": "evaluations/security/m7_5_live_cases.json",
        "repetitions": args.repetitions,
        "planned_converse_calls": planned,
        "completed_runs": len(records),
        "total_converse_calls": sum(r.converse_calls for r in records),
        "summary": summary,
        "runs": live.records_to_json(records),
    }
    ARTIFACT.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary["totals"]))
    print(f"wrote {ARTIFACT.relative_to(REPO_ROOT)}")
    return 0


def guarded_main(args: argparse.Namespace) -> int:
    """M7.6: the same cases with one pinned guardrail version on every call.

    Fails closed before any Bedrock call if the guardrail configuration is
    incomplete; never falls back to unguarded mode.
    """
    os.environ["BEDROCK_MODEL_ID"] = args.model_id
    os.environ["LOG_FULL_CONTENT"] = "false"
    os.environ.setdefault("LOG_LEVEL", "WARNING")
    for name in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
        os.environ.pop(name, None)

    from evaluations.live import m7_5_baseline as live
    from evaluations.live import m7_6_guardrails as guarded

    try:
        settings = guarded.GuardrailSettings.require(args.guardrail_id, args.guardrail_version)
    except guarded.GuardrailConfigError as exc:
        print(f"refusing: {exc}")
        return 2

    cases = live.load_cases()
    planned = len(cases) * args.repetitions
    print(live.ID01_STATEMENT)
    print(
        f"M7.6 guarded mode: guardrail={settings.guardrail_id} "
        f"version={settings.guardrail_version} cases={len(cases)} "
        f"repetitions={args.repetitions} planned_converse_calls={planned}"
    )
    if args.plan:
        return 0
    if planned > MAX_PLANNED_CALLS:
        print(f"refusing: planned calls {planned} exceed cap {MAX_PLANNED_CALLS}")
        return 2
    if not args.confirm_live:
        print("refusing: pass --confirm-live to make live Bedrock calls")
        return 2
    if not args.model_id or args.model_id == PLACEHOLDER_MODEL:
        print("refusing: set --model-id to a real Bedrock model or inference profile")
        return 2

    import boto3

    from app.core.config import get_settings

    app_settings = get_settings()
    if app_settings.bedrock_model_id != args.model_id or app_settings.log_full_content:
        print("refusing: settings did not pick up the pinned configuration")
        return 2
    region = app_settings.aws_region

    raw_dir = Path(args.raw_dir) if args.raw_dir else None
    if raw_dir is not None:
        if REPO_ROOT in raw_dir.resolve().parents or raw_dir.resolve() == REPO_ROOT:
            print("refusing: --raw-dir must be outside the repository")
            return 2
        raw_dir.mkdir(parents=True, exist_ok=True)

    def raw_sink(case_id: str, repetition: int, text: str) -> None:
        if raw_dir is not None:
            (raw_dir / f"{case_id}-r{repetition}.txt").write_text(text, encoding="utf-8")

    def client() -> object:
        return boto3.client("bedrock-runtime", region_name=region)

    baseline_outcomes = guarded.load_m7_5_outcomes()
    records = []
    for case in cases:
        for repetition in range(1, args.repetitions + 1):
            record = guarded.run_case_guarded(
                case, repetition, args.model_id, settings, client, baseline_outcomes, raw_sink
            )
            records.append(record)
            print(f"{record.case_id} r{repetition}: {record.outcome} ({record.reason})")
            if record.converse_calls and not (
                record.guardrail_config_present and record.guarded_request_valid
            ):
                print("aborting: a call was not sent with the pinned guardrail; comparison invalid")
                return 3
            if record.error_type and record.error_type not in live.TRANSIENT_CODES:
                print(f"aborting: non-transient Bedrock error {record.error_type}")
                break
        else:
            continue
        break

    summary = guarded.summarize(records)
    artifact = {
        "milestone": "M7.6",
        "statement": live.ID01_STATEMENT,
        "guardrail": {
            "id": settings.guardrail_id,
            "version": settings.guardrail_version,
            "definition_file": "evaluations/security/m7_6_guardrail_definition.json",
            "trace_mode": guarded.TRACE_MODE,
            "enforcement": "evaluation only; not enforced by IAM or on any runtime path",
        },
        "qualifiers": {
            "question": list(guarded.QUERY_QUALIFIERS),
            "passages": list(guarded.GROUNDING_QUALIFIERS),
            "system_prompt": "not guardContent; not evaluated",
        },
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "generation_model_id": args.model_id,
        "embedding_model_id": "not used: retrieval pinned by fixture store",
        "region": region,
        "system_prompt": "production SYSTEM_PROMPT plus one test-only canary sentence",
        "cases_file": "evaluations/security/m7_5_live_cases.json",
        "baseline_artifact": "evaluations/security/m7_5_live_baseline.json",
        "repetitions": args.repetitions,
        "planned_converse_calls": planned,
        "completed_runs": len(records),
        "total_converse_calls": sum(r.converse_calls for r in records),
        "summary": summary,
        "runs": guarded.records_to_json(records),
    }
    GUARDED_ARTIFACT.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary["totals"]))
    print(json.dumps(summary["guardrail"]))
    print(f"wrote {GUARDED_ARTIFACT.relative_to(REPO_ROOT)}")
    return 0


def experiment_main(args: argparse.Namespace) -> int:
    """M7.6b: one pinned experiment (cases, guardrail version, repetitions).

    Writes only evaluations/security/m7_6b_guardrails_tuning.json and refuses
    to rerun an experiment that is already recorded.
    """
    os.environ["BEDROCK_MODEL_ID"] = args.model_id
    os.environ["LOG_FULL_CONTENT"] = "false"
    os.environ.setdefault("LOG_LEVEL", "WARNING")
    for name in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
        os.environ.pop(name, None)

    from evaluations.live import m7_5_baseline as live
    from evaluations.live import m7_6_guardrails as guarded
    from evaluations.live import m7_6b_tuning as tuning

    experiment = tuning.EXPERIMENTS[args.experiment]
    try:
        settings = guarded.GuardrailSettings.require(args.guardrail_id, args.guardrail_version)
    except guarded.GuardrailConfigError as exc:
        print(f"refusing: {exc}")
        return 2
    if (settings.guardrail_id, settings.guardrail_version) != (
        tuning.GUARDRAIL_ID,
        experiment.guardrail_version,
    ):
        print(
            f"refusing: experiment {experiment.key} is pinned to guardrail "
            f"{tuning.GUARDRAIL_ID} version {experiment.guardrail_version}"
        )
        return 2
    if args.repetitions != tuning.REPETITIONS:
        print(f"refusing: experiment repetitions are pinned to {tuning.REPETITIONS}")
        return 2
    if tuning.already_recorded(experiment.key):
        print(f"refusing: experiment {experiment.key} is already recorded; no reruns")
        return 2

    cases = tuning.select_cases(experiment, live.load_cases())
    print(live.ID01_STATEMENT)
    print(
        f"{experiment.label}: guardrail={settings.guardrail_id} "
        f"version={settings.guardrail_version}"
    )
    print(f"cases ({len(cases)}): {', '.join(c['id'] for c in cases)}")
    print(f"repetitions={tuning.REPETITIONS} planned_converse_calls={experiment.planned_calls}")
    if args.plan:
        return 0
    if not args.confirm_live:
        print("refusing: pass --confirm-live to make live Bedrock calls")
        return 2
    if not args.model_id or args.model_id == PLACEHOLDER_MODEL:
        print("refusing: set --model-id to a real Bedrock model or inference profile")
        return 2

    import boto3

    from app.core.config import get_settings

    app_settings = get_settings()
    if app_settings.bedrock_model_id != args.model_id or app_settings.log_full_content:
        print("refusing: settings did not pick up the pinned configuration")
        return 2
    region = app_settings.aws_region

    raw_dir = Path(args.raw_dir) if args.raw_dir else None
    if raw_dir is not None:
        if REPO_ROOT in raw_dir.resolve().parents or raw_dir.resolve() == REPO_ROOT:
            print("refusing: --raw-dir must be outside the repository")
            return 2
        raw_dir.mkdir(parents=True, exist_ok=True)

    def raw_sink(case_id: str, repetition: int, text: str) -> None:
        if raw_dir is not None:
            name = f"{experiment.key}-{case_id}-r{repetition}.txt"
            (raw_dir / name).write_text(text, encoding="utf-8")

    def client() -> object:
        return boto3.client("bedrock-runtime", region_name=region)

    baseline_outcomes = guarded.load_m7_5_outcomes()
    records = []
    for case in cases:
        for repetition in range(1, tuning.REPETITIONS + 1):
            record = guarded.run_case_guarded(
                case, repetition, args.model_id, settings, client, baseline_outcomes, raw_sink
            )
            records.append(record)
            print(f"{record.case_id} r{repetition}: {record.outcome} ({record.reason})")
            if record.converse_calls and not (
                record.guardrail_config_present and record.guarded_request_valid
            ):
                print("aborting: a call was not sent with the pinned guardrail; experiment invalid")
                return 3
            if record.error_type and record.error_type not in live.TRANSIENT_CODES:
                print(f"aborting: non-transient Bedrock error {record.error_type}")
                break
        else:
            continue
        break

    summary = tuning.experiment_summary(experiment, records)
    entry = {
        "label": experiment.label,
        "statement": live.ID01_STATEMENT,
        "guardrail": {
            "id": settings.guardrail_id,
            "version": settings.guardrail_version,
            "definition_file": experiment.definition_file,
            "trace_mode": guarded.TRACE_MODE,
            "enforcement": "evaluation only; not enforced by IAM or on any runtime path",
        },
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "generation_model_id": args.model_id,
        "region": region,
        "cases": list(experiment.case_ids),
        "repetitions": tuning.REPETITIONS,
        "planned_converse_calls": experiment.planned_calls,
        "completed_runs": len(records),
        "total_converse_calls": sum(r.converse_calls for r in records),
        "summary": summary,
        "runs": guarded.records_to_json(records),
    }
    tuning.write_experiment(entry, experiment.key)
    print(json.dumps(summary["totals"]))
    print(json.dumps(summary["guardrail"]))
    if "verdict" in summary:
        print(json.dumps(summary["verdict"]))
    print(f"wrote {tuning.ARTIFACT_PATH.relative_to(REPO_ROOT)} (experiment {experiment.key})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
