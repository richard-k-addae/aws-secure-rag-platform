"""M8.5 live Cognito validation of the production JWT verifier (R-01 .. R-18).

Usage (each live step needs its own explicit authorization):
  python scripts/validate_live_cognito.py --expected-account-id <acct> --user-pool-id <id> \
      --app-client-id <id> --other-client-id <id>   # plan only: no AWS call
  python scripts/validate_live_cognito.py <same args> --confirm-live
  python scripts/validate_live_cognito.py <same args> --cleanup-only --run-id <id>
  python scripts/validate_live_cognito.py <same args> --cleanup-only --all-runs

Before any Cognito call the harness runs sts:GetCallerIdentity and refuses (exit 4)
unless the credentials are an assumed-role session of --expected-role-name in
--expected-account-id.

Targets only the temporary identity-eval pool (infrastructure/environments/
identity-eval); refuses any pool without its name prefix and tags. Creates ten
synthetic users, always deletes them, and exits non-zero with
INCOMPLETE_CLEANUP when deletion cannot be independently verified.

Never prints, logs or stores passwords or tokens. Never part of CI.

Exit codes: 0 PASS, 1 FAIL, 2 INCOMPLETE_CLEANUP, 3 INTERRUPTED/INCOMPLETE/ERROR,
4 guard or configuration refusal (nothing created).
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from evaluations.live import m8_5_cognito as harness  # noqa: E402

DEFAULT_EVIDENCE = REPO_ROOT / "evaluations" / "security" / "m8_5_live_cognito.json"
DEFAULT_MANIFEST_DIR = Path(tempfile.gettempdir()) / "m85-identity-eval"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--expected-account-id",
        default="",
        help="12-digit evaluation account; credentials from any other account are refused",
    )
    parser.add_argument("--expected-role-name", default=harness.DEFAULT_HARNESS_ROLE)
    parser.add_argument("--user-pool-id", required=True)
    parser.add_argument("--app-client-id", required=True)
    parser.add_argument("--other-client-id", required=True)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--manifest-dir", type=Path, default=DEFAULT_MANIFEST_DIR)
    parser.add_argument("--skip-expiry", action="store_true", help="R-10 recorded as SKIPPED")
    parser.add_argument("--rls-database-url", default="", help="disposable PostgreSQL for R-15")
    parser.add_argument("--rls-dimensions", type=int, default=4)
    parser.add_argument("--confirm-live", action="store_true", help="required for AWS calls")
    parser.add_argument("--cleanup-only", action="store_true", help="recovery: delete users only")
    parser.add_argument("--all-runs", action="store_true", help="with --cleanup-only: any run")
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> "harness.HarnessConfig":
    run_id = args.run_id or ("recovery" if args.cleanup_only else harness.new_run_id())
    return harness.HarnessConfig(
        region=args.region,
        user_pool_id=args.user_pool_id,
        app_client_id=args.app_client_id,
        other_client_id=args.other_client_id,
        run_id=run_id,
        expected_account_id=args.expected_account_id,
        expected_role_name=args.expected_role_name,
        skip_expiry=args.skip_expiry,
    )


def main(
    argv: list[str] | None = None, client_factory: object = None, sts_factory: object = None
) -> int:
    args = parse_args(argv)
    if args.cleanup_only and not args.all_runs and not args.run_id:
        print("--cleanup-only needs --run-id or --all-runs")
        return 4
    try:
        config = build_config(args)
    except harness.HarnessError as exc:
        print(f"refused: {exc}")
        return 4
    manifest = args.manifest_dir / f"{config.run_id}.json"
    if not args.confirm_live:
        mode = "cleanup-only" if args.cleanup_only else "full validation"
        print(f"PLAN ({mode}); no AWS call made. Re-run with --confirm-live after approval.")
        print(f"  pool={config.user_pool_id} region={config.region} run_id={config.run_id}")
        print(f"  account={config.expected_account_id} role={config.expected_role_name}")
        print(f"  users={len(harness.USERS)} prefix={config.run_prefix} manifest={manifest}")
        return 0
    if client_factory is None:
        import boto3

        # One session so the account check and every Cognito call share credentials.
        session = boto3.Session(region_name=config.region)
        client = session.client("cognito-idp")
        sts_client = session.client("sts")
    else:
        client = client_factory()  # type: ignore[operator]
        sts_client = sts_factory() if sts_factory is not None else None  # type: ignore[operator]
    try:
        if args.cleanup_only:
            code, report = harness.cleanup_only(
                config,
                client,
                sts_client=sts_client,
                manifest_path=manifest,
                all_runs=args.all_runs,
            )
            print(json.dumps({"cleanup": report}, indent=2, sort_keys=True))
            return code
        rls = (
            harness.RlsOptions(args.rls_database_url, args.rls_dimensions)
            if args.rls_database_url
            else None
        )
        code, document = harness.run(
            config,
            client,
            sts_client=sts_client,
            evidence_path=args.evidence,
            manifest_path=manifest,
            rls=rls,
        )
    except harness.GuardError as exc:
        print(f"refused: {exc}")
        return 4
    except harness.EvidenceLeakError as exc:
        print(str(exc))
        return 1
    print(f"run_id={config.run_id} overall={document['overall']} evidence={args.evidence}")
    for case in document["cases"]:
        print(f"  {case['id']}: {case['status']}")
    print(f"  cleanup verified: {document['cleanup'].get('verified')}")
    if not document["cleanup"].get("verified"):
        print(f"  RECOVERY: --cleanup-only --run-id {config.run_id} (manifest kept: {manifest})")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
