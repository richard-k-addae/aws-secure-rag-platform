"""M7.5 live adversarial baseline WITHOUT Bedrock Guardrails (non-blocking).

Usage:
  python scripts/run_live_adversarial_baseline.py --plan
  python scripts/run_live_adversarial_baseline.py --confirm-live --model-id <id>

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
MAX_PLANNED_CALLS = 60


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", action="store_true", help="print the plan; make no calls")
    parser.add_argument("--confirm-live", action="store_true", help="required for live calls")
    parser.add_argument("--model-id", default=os.environ.get("BEDROCK_MODEL_ID", ""))
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--raw-dir", default="", help="local-only dir for raw synthetic output")
    args = parser.parse_args()

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


if __name__ == "__main__":
    sys.exit(main())
