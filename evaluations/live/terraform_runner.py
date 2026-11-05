"""M8.5 identity-eval Terraform execution wrapper (fail closed).

The only supported way to run Terraform against infrastructure/environments/
identity-eval. It exists because the Terraform root has no credential
configuration: left alone, Terraform would silently use the default AWS profile
(a long-lived administrator identity) and ``allowed_account_ids`` only checks the
account, not the credential type.

Operations (nothing else is accepted; there is no argument pass-through):

  plan          terraform plan -out=<name>.tfplan
  plan-destroy  terraform plan -destroy -out=<name>.tfplan
  apply         terraform apply of an EXISTING saved plan, SHA-256 pinned

Before Terraform is invoked the wrapper requires, in order:

* a Terraform root whose provider keeps ``allowed_account_ids`` and carries no
  credential, endpoint or assume-role settings, and has no override/auto-vars files;
* for ``apply``: the plan file's SHA-256 equals ``--plan-sha256`` (checked on a
  private copy that is then the file applied) and the plan archive is structurally
  sound: only the expected entries, a single root module, and an embedded
  configuration and lock file identical to the reviewed root;
* temporary credentials exported as AWS_ACCESS_KEY_ID (ASIA...), AWS_SECRET_ACCESS_KEY
  and AWS_SESSION_TOKEN plus a timezone-aware AWS_CREDENTIAL_EXPIRATION with enough
  lifetime left for the operation (20 minutes to plan, 30 to apply);
* ``sts:GetCallerIdentity`` using exactly those credentials returns an assumed-role
  session of ``rag-eval-terraform`` in ``--expected-account-id``.

Only then is Terraform run, and every saved plan is inspected with
``terraform show -json`` (read-only, no AWS call) before it can be trusted: the plan's
variables must name the expected account, the aws provider must still take
``allowed_account_ids`` from ``var.expected_account_id`` with no other credential
settings, and the planned changes must be exactly the evaluation Cognito resources
with a single direction (create or delete). ``apply`` never runs on a plan that fails
this; a freshly created plan that fails it is reported and its hash is not printed.

Terraform runs with a rebuilt environment: every inherited AWS_* and TF_*
variable is dropped, AWS_PROFILE is unset, the shared credentials/config files point
at empty private files and the metadata service is disabled, so no default-profile
credential can be picked up. Credential values are never printed, logged or
recorded; Terraform output is scrubbed before it is shown.

Without --confirm-live nothing is contacted or executed (dry run).

Exit codes: 0 success, 1 Terraform failed, 4 refused (the operation was not run),
5 a newly created plan failed structural verification (do not apply it).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from evaluations.live.aws_identity import (
    ACCOUNT_ID_PATTERN,
    IdentityGuardError,
    verify_assumed_role,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL_ROOT = REPO_ROOT / "infrastructure" / "environments" / "identity-eval"
TERRAFORM_ROLE = "rag-eval-terraform"
REGION = "us-east-1"
# Lifetime that must remain when an operation starts. Plan/apply of nine Cognito
# resources takes minutes; the margin absorbs review pauses and clock skew.
MIN_REMAINING_SECONDS = {"plan": 20 * 60, "plan-destroy": 20 * 60, "apply": 30 * 60}
# The longest role session is 12 hours; a farther expiry is a mistake or a spoof.
MAX_REMAINING_SECONDS = 12 * 3600 + 300
MAX_PLAN_BYTES = 16 * 1024 * 1024
MAX_SHOW_BYTES = 8 * 1024 * 1024
EXIT_OK, EXIT_TERRAFORM_FAILED, EXIT_REFUSED, EXIT_PLAN_UNVERIFIED = 0, 1, 4, 5

CREDENTIAL_VARS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
EXPIRATION_VAR = "AWS_CREDENTIAL_EXPIRATION"
PLAN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,60}\.tfplan")
# The exact resources the evaluation root may create or delete.
EXPECTED_RESOURCES = {
    "aws_cognito_user_pool": 1,
    "aws_cognito_user_group": 6,
    "aws_cognito_user_pool_client": 2,
}
PLAN_VARIABLES = frozenset({"aws_region", "expected_account_id", "expires_on"})
PROVIDER_EXPRESSIONS = frozenset({"allowed_account_ids", "default_tags", "region"})
AWS_PROVIDER = "registry.terraform.io/hashicorp/aws"
REQUIRED_POOL_TAGS = {"Environment": "identity-eval", "Ephemeral": "true", "Milestone": "M8.5"}
POOL_NAME_PREFIX = "rag-identity-eval-m85"
PLAN_ENTRY = re.compile(r"tfconfig/m-/(?P<name>[A-Za-z0-9_.-]+\.tf)")
PLAN_FIXED_ENTRIES = frozenset(
    {"tfplan", "tfstate", "tfstate-prev", ".terraform.lock.hcl", "tfconfig/modules.json"}
)
PLAN_REQUIRED_ENTRIES = frozenset({"tfplan", ".terraform.lock.hcl", "tfconfig/modules.json"})
ALLOWED_ACCOUNTS_LINE = re.compile(r"allowed_account_ids\s*=\s*\[\s*var\.expected_account_id\s*\]")
# Provider settings that would route credentials or weaken the account safeguard.
FORBIDDEN_SETTING = re.compile(
    r"(?m)^\s*(profile|access_key|secret_key|token|shared_credentials_files?|"
    r"shared_config_files|skip_credentials_validation|skip_requesting_account_id|"
    r"skip_metadata_api_check|forbidden_account_ids|insecure)\s*="
)
FORBIDDEN_BLOCK = re.compile(
    r"(?m)^\s*(assume_role|assume_role_with_web_identity|endpoints)\s*[{=]|^\s*module\s+\""
)
# Files Terraform loads implicitly and that could change the provider or variables.
IMPLICIT_FILES = re.compile(
    r"(?i)(terraform\.tfvars(\.json)?|.*\.auto\.tfvars(\.json)?|override\.tf(\.json)?|"
    r".*_override\.tf(\.json)?)"
)
KEY_SHAPE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")


class RefusedError(Exception):
    """A precondition failed; the operation was not run. Never carries secret material."""


class PlanVerificationError(RefusedError):
    """A saved plan failed structural verification. Reason codes only."""


@dataclass(frozen=True)
class Credentials:
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    session_token: str = field(repr=False)
    expires_at: datetime | None = field(default=None, repr=False)

    def secrets(self) -> tuple[str, ...]:
        return (self.access_key_id, self.secret_access_key, self.session_token)

    def require_lifetime(self, operation: str, now: datetime) -> None:
        if self.expires_at is None:
            raise RefusedError("credential expiration is missing")
        remaining = (self.expires_at - now).total_seconds()
        if remaining < MIN_REMAINING_SECONDS[operation]:
            minutes = MIN_REMAINING_SECONDS[operation] // 60
            raise RefusedError(
                f"credentials are expired or have under {minutes} minutes left for {operation}"
            )
        if remaining > MAX_REMAINING_SECONDS:
            raise RefusedError("credential expiration is implausibly far in the future")


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[list[str], Path, Mapping[str, str]], RunResult]
StsFactory = Callable[[Credentials], Any]


# --- preconditions -------------------------------------------------------------------


def check_configuration_text(text: str) -> None:
    """Shared by the live root and the configuration snapshot embedded in a saved plan."""
    stripped = _strip_comments(text)
    if not ALLOWED_ACCOUNTS_LINE.search(stripped):
        raise RefusedError("terraform allowed_account_ids safeguard is missing")
    if FORBIDDEN_SETTING.search(stripped) or FORBIDDEN_BLOCK.search(stripped):
        raise RefusedError("terraform provider carries credential or endpoint settings")


def _normalized(data: bytes | str) -> str:
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    return text.replace("\r\n", "\n")


def read_root_configuration(root: Path) -> dict[str, str]:
    """The reviewed root: ``*.tf`` files by name, with line endings normalized."""
    if not root.is_dir():
        raise RefusedError("terraform root not found")
    for entry in root.iterdir():
        if entry.is_file() and IMPLICIT_FILES.fullmatch(entry.name):
            raise RefusedError("terraform root has an implicit variable or override file")
    sources = sorted(root.glob("*.tf"))
    if not sources:
        raise RefusedError("terraform root has no configuration")
    return {p.name: _normalized(p.read_text(encoding="utf-8")) for p in sources}


def check_terraform_root(root: Path) -> None:
    """The root must keep its account safeguard and carry no credential routing."""
    check_configuration_text("\n".join(read_root_configuration(root).values()))


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"(?m)(#|//).*$", "", text)


def load_credentials(
    env: Mapping[str, str], operation: str, now: Callable[[], datetime]
) -> Credentials:
    values = [env.get(name, "").strip() for name in CREDENTIAL_VARS]
    if not all(values):
        raise RefusedError("temporary role credentials are missing")
    key_id, secret, token = values
    if not re.fullmatch(r"ASIA[A-Z0-9]{16}", key_id):
        raise RefusedError("credentials are not temporary role-session credentials")
    raw = env.get(EXPIRATION_VAR, "").strip()
    if not raw:
        raise RefusedError("credential expiration is required (export AWS_CREDENTIAL_EXPIRATION)")
    try:
        expires = datetime.fromisoformat(raw)
    except ValueError:
        raise RefusedError("credential expiration is malformed") from None
    if expires.tzinfo is None or expires.utcoffset() is None:
        raise RefusedError("credential expiration must include a timezone")
    creds = Credentials(key_id, secret, token, expires.astimezone(UTC))
    creds.require_lifetime(operation, now())
    return creds


def build_environment(
    base: Mapping[str, str], creds: Credentials, config_dir: Path
) -> dict[str, str]:
    """Rebuild the child environment so no inherited AWS or Terraform setting survives."""
    env = {k: v for k, v in base.items() if not k.upper().startswith(("AWS_", "TF_"))}
    env.pop("CHECKPOINT_DISABLE", None)
    empty_credentials, empty_config = config_dir / "credentials", config_dir / "config"
    empty_cli_config = config_dir / "terraformrc"
    for empty in (empty_credentials, empty_config, empty_cli_config):
        empty.write_text("", encoding="utf-8")
    env.update(
        {
            "AWS_ACCESS_KEY_ID": creds.access_key_id,
            "AWS_SECRET_ACCESS_KEY": creds.secret_access_key,
            "AWS_SESSION_TOKEN": creds.session_token,
            "AWS_REGION": REGION,
            "AWS_DEFAULT_REGION": REGION,
            "AWS_SHARED_CREDENTIALS_FILE": str(empty_credentials),
            "AWS_CONFIG_FILE": str(empty_config),
            "AWS_EC2_METADATA_DISABLED": "true",
            # A user-level CLI config (dev_overrides, provider mirrors) must not apply.
            "TF_CLI_CONFIG_FILE": str(empty_cli_config),
            "TF_IN_AUTOMATION": "1",
            "TF_INPUT": "0",
            "CHECKPOINT_DISABLE": "1",
        }
    )
    return env


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_plan_archive(path: Path, root: Path) -> None:
    """Structural checks on a saved plan's zip that need no Terraform and no credentials.

    The archive must contain only the entries Terraform writes, describe a single root
    module, and embed a configuration and lock file identical to the reviewed root.
    """
    reviewed = read_root_configuration(root)
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(set(names)) != len(names):
                raise PlanVerificationError("saved plan has duplicate entries")
            embedded: dict[str, str] = {}
            total = 0
            for info in infos:
                match = PLAN_ENTRY.fullmatch(info.filename)
                if info.filename not in PLAN_FIXED_ENTRIES and match is None:
                    raise PlanVerificationError("saved plan has an unexpected entry")
                if info.flag_bits & 0x1 or info.is_dir():
                    raise PlanVerificationError("saved plan has an unreadable entry")
                total += info.file_size
                if info.file_size > MAX_PLAN_BYTES or total > 2 * MAX_PLAN_BYTES:
                    raise PlanVerificationError("saved plan is unexpectedly large")
                if match is not None:
                    embedded[match["name"]] = _normalized(archive.read(info))
            if not PLAN_REQUIRED_ENTRIES <= set(names):
                raise PlanVerificationError("saved plan is missing required entries")
            if not archive.read("tfplan"):
                raise PlanVerificationError("saved plan is empty")
            modules = json.loads(archive.read("tfconfig/modules.json"))
            lock = _normalized(archive.read(".terraform.lock.hcl"))
    except (zipfile.BadZipFile, OSError, ValueError, KeyError, RuntimeError):
        raise PlanVerificationError("saved plan is not a readable Terraform plan") from None
    if not (
        isinstance(modules, list)
        and len(modules) == 1
        and modules[0].get("Key") == ""
        and modules[0].get("Dir") == "."
    ):
        raise PlanVerificationError("saved plan describes more than the root module")
    check_configuration_text("\n".join(embedded.values()))
    if embedded != reviewed:
        raise PlanVerificationError("saved plan configuration differs from the reviewed root")
    root_lock = root / ".terraform.lock.hcl"
    if not root_lock.is_file() or _normalized(root_lock.read_text(encoding="utf-8")) != lock:
        raise PlanVerificationError("saved plan lock file differs from the reviewed root")


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise PlanVerificationError(reason)


def verify_plan_document(doc: Any, *, account_id: str, direction: str | None) -> str:
    """Check ``terraform show -json`` output of a saved plan; return create or delete."""
    try:
        return _verify_plan_document(doc, account_id, direction)
    except PlanVerificationError:
        raise
    except (KeyError, TypeError, AttributeError, ValueError, IndexError):
        raise PlanVerificationError("plan JSON has an unexpected structure") from None


def _verify_plan_document(doc: Any, account_id: str, direction: str | None) -> str:
    _require(isinstance(doc, dict), "plan JSON has an unexpected structure")
    _require(str(doc["format_version"]).startswith("1."), "unsupported plan format")
    _require(doc.get("errored") is False and doc.get("applyable") is True, "plan is not applyable")
    _require(doc.get("complete") is not False, "plan is incomplete")

    variables = doc["variables"]
    _require(
        set(variables) <= PLAN_VARIABLES
        and {"expected_account_id", "expires_on"} <= set(variables),
        "plan has unexpected variables",
    )
    _require(
        variables["expected_account_id"]["value"] == account_id,
        "plan was not created for the expected account",
    )
    expires_on = variables["expires_on"]["value"]
    _require(
        isinstance(expires_on, str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires_on) is not None
        and date.fromisoformat(expires_on).isoformat() == expires_on,
        "plan expires_on is not a date",
    )
    _require(
        "aws_region" not in variables or variables["aws_region"]["value"] == REGION,
        "plan region is not approved",
    )

    configuration = doc["configuration"]
    providers = configuration["provider_config"]
    _require(set(providers) == {"aws"}, "plan configures unexpected providers")
    aws = providers["aws"]
    _require(aws["full_name"] == AWS_PROVIDER, "plan uses an unexpected provider")
    expressions = aws["expressions"]
    _require(set(expressions) <= PROVIDER_EXPRESSIONS, "plan provider has extra settings")
    guard = expressions["allowed_account_ids"]
    _require(
        set(guard) == {"references"} and set(guard["references"]) == {"var.expected_account_id"},
        "plan provider does not take allowed_account_ids from the expected account variable",
    )
    _require(
        "region" not in expressions
        or set(expressions["region"].get("references", [])) == {"var.aws_region"},
        "plan provider region is not the region variable",
    )
    root_module = configuration["root_module"]
    _require(not root_module.get("module_calls"), "plan calls other modules")
    for resource in root_module.get("resources", []):
        _require(
            resource["mode"] == "managed" and resource["type"] in EXPECTED_RESOURCES,
            "plan configures unexpected resources",
        )

    changes = doc["resource_changes"]
    _require(isinstance(changes, list) and bool(changes), "plan has no changes")
    action_sets = {tuple(change["change"]["actions"]) for change in changes}
    _require(len(action_sets) == 1, "plan mixes different actions")
    (actions,) = action_sets
    _require(actions in {("create",), ("delete",)}, "plan actions are not create or delete")
    kind: str = actions[0]
    _require(direction in (None, kind), f"plan is not a {direction} plan")
    counts: dict[str, int] = {}
    for change in changes:
        _require(
            change["mode"] == "managed"
            and change["type"] in EXPECTED_RESOURCES
            and change["provider_name"] == AWS_PROVIDER,
            "plan changes unexpected resources",
        )
        counts[change["type"]] = counts.get(change["type"], 0) + 1
    if kind == "create":
        _require(counts == EXPECTED_RESOURCES, "plan does not create exactly the nine resources")
    else:
        _require(
            all(counts[t] <= EXPECTED_RESOURCES[t] for t in counts),
            "plan deletes too many resources",
        )
    for change in changes:
        _verify_resource(change, kind, expires_on)
    return kind


def _verify_resource(change: dict[str, Any], kind: str, expires_on: str) -> None:
    detail = change["change"]
    if kind == "delete":
        if change["type"] == "aws_cognito_user_pool":
            tags = detail["before"]["tags_all"]
            _require(
                all(tags.get(k) == v for k, v in REQUIRED_POOL_TAGS.items()),
                "plan deletes a pool that is not the tagged evaluation pool",
            )
        return
    after = detail["after"]
    if change["type"] == "aws_cognito_user_pool":
        tags = after["tags_all"]
        _require(
            all(tags.get(k) == v for k, v in REQUIRED_POOL_TAGS.items())
            and tags.get("ExpiresOn") == expires_on,
            "planned pool is missing the evaluation tags",
        )
        _require(after["deletion_protection"] == "INACTIVE", "planned pool is deletion protected")
        _require(str(after["name"]).startswith(POOL_NAME_PREFIX), "planned pool name is wrong")
    elif change["type"] == "aws_cognito_user_pool_client":
        _require(after["generate_secret"] is False, "planned client has a secret")


def inspect_saved_plan(
    runner: Runner,
    plan_file: Path,
    root: Path,
    env: Mapping[str, str],
    *,
    account_id: str,
    direction: str | None,
) -> str:
    """Read the plan with ``terraform show -json`` (read-only) and verify it."""
    result = runner(["terraform", "show", "-json", "-no-color", str(plan_file)], root, env)
    if result.returncode != 0 or not result.stdout.strip():
        raise PlanVerificationError("terraform could not read the saved plan")
    if len(result.stdout) > MAX_SHOW_BYTES:
        raise PlanVerificationError("plan JSON is unexpectedly large")
    try:
        document = json.loads(result.stdout)
    except (ValueError, RecursionError):
        raise PlanVerificationError("plan JSON is not valid") from None
    return verify_plan_document(document, account_id=account_id, direction=direction)


def prepare_plan(root: Path, name: str, expected_sha256: str, tmp: Path) -> Path:
    """Copy the plan to a private directory, then verify and return that copy.

    Verifying the copy that is then applied closes the check-then-use window.
    """
    source = root / name
    if source.is_symlink() or not source.is_file():
        raise RefusedError("saved plan file not found")
    copy = tmp / name
    shutil.copyfile(source, copy)
    if not hmac.compare_digest(sha256_of(copy), expected_sha256.lower()):
        raise RefusedError("saved plan SHA-256 does not match; it was modified or replaced")
    inspect_plan_archive(copy, root)
    return copy


def scrub(text: str, secrets: tuple[str, ...]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return KEY_SHAPE.sub("[REDACTED]", text)


# --- arguments -----------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:
        raise RefusedError(f"invalid arguments: {message}")


def build_parser() -> argparse.ArgumentParser:
    common = _Parser(add_help=False, allow_abbrev=False)
    common.add_argument("--expected-account-id", required=True)
    common.add_argument("--confirm-live", action="store_true", help="required to contact AWS")
    common.add_argument("--record", type=Path, help="write a credential-free run record")
    planning = _Parser(add_help=False, allow_abbrev=False)
    planning.add_argument("--expires-on", required=True, help="YYYY-MM-DD ExpiresOn tag")
    planning.add_argument("--out", required=True, help="new plan file name, ends in .tfplan")

    parser = _Parser(description=(__doc__ or "").splitlines()[0], allow_abbrev=False)
    sub = parser.add_subparsers(dest="operation", required=True, parser_class=_Parser)
    sub.add_parser("plan", parents=[common, planning], allow_abbrev=False)
    sub.add_parser("plan-destroy", parents=[common, planning], allow_abbrev=False)
    apply_parser = sub.add_parser("apply", parents=[common], allow_abbrev=False)
    apply_parser.add_argument("--plan", required=True, help="existing saved plan file name")
    apply_parser.add_argument("--plan-sha256", required=True)
    return parser


def validate_arguments(args: argparse.Namespace, root: Path) -> None:
    if not re.fullmatch(ACCOUNT_ID_PATTERN, args.expected_account_id):
        raise RefusedError("expected account id must be a 12-digit AWS account id")
    if args.operation == "apply":
        if not PLAN_NAME.fullmatch(args.plan):
            raise RefusedError("plan must be a plain *.tfplan file name in the root")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", args.plan_sha256):
            raise RefusedError("plan-sha256 must be 64 hexadecimal characters")
        return
    if not PLAN_NAME.fullmatch(args.out):
        raise RefusedError("out must be a plain *.tfplan file name in the root")
    if (root / args.out).exists():
        raise RefusedError("out already exists; a saved plan is never overwritten")
    try:
        parsed = date.fromisoformat(args.expires_on)
    except ValueError:
        raise RefusedError("expires-on must be a YYYY-MM-DD date") from None
    if parsed.isoformat() != args.expires_on:
        raise RefusedError("expires-on must be a YYYY-MM-DD date")


def terraform_command(args: argparse.Namespace, plan_file: Path | None) -> list[str]:
    base = ["terraform", "apply" if args.operation == "apply" else "plan"]
    base += ["-input=false", "-lock=true", "-no-color"]
    if args.operation == "apply":
        assert plan_file is not None  # noqa: S101 - guaranteed by the apply branch
        return [*base, str(plan_file)]
    if args.operation == "plan-destroy":
        base.append("-destroy")
    return [
        *base,
        f"-out={args.out}",
        "-var",
        f"expected_account_id={args.expected_account_id}",
        "-var",
        f"expires_on={args.expires_on}",
    ]


# --- default (live) collaborators ------------------------------------------------------


def default_sts_factory(creds: Credentials) -> Any:
    import boto3
    from botocore.config import Config

    # Explicit credentials: the default chain (and any profile) is never consulted.
    return boto3.client(
        "sts",
        region_name=REGION,
        aws_access_key_id=creds.access_key_id,
        aws_secret_access_key=creds.secret_access_key,
        aws_session_token=creds.session_token,
        config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2}),
    )


def subprocess_runner(argv: list[str], cwd: Path, env: Mapping[str, str]) -> RunResult:
    executable = shutil.which(argv[0])
    if executable is None:
        raise RefusedError("terraform executable not found")
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [executable, *argv[1:]],
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return RunResult(proc.returncode, proc.stdout, proc.stderr)


# --- orchestration ---------------------------------------------------------------------


def _write_record(path: Path, payload: dict[str, Any], secrets: tuple[str, ...]) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True)
    if scrub(text, secrets) != text:
        raise RefusedError("run record contained credential material and was not written")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


def _execute(
    argv: list[str] | None,
    *,
    env: Mapping[str, str],
    sts_factory: StsFactory,
    runner: Runner,
    now: Callable[[], datetime],
    root: Path,
) -> int:
    args = build_parser().parse_args(argv)
    validate_arguments(args, root)
    check_terraform_root(root)
    started = now().isoformat(timespec="seconds")
    expected_direction = {"plan": "create", "plan-destroy": "delete", "apply": None}[args.operation]
    with tempfile.TemporaryDirectory(prefix="m85-tf-") as tmp_name:
        tmp = Path(tmp_name)
        plan_copy: Path | None = None
        plan_sha: str | None = None
        if args.operation == "apply":
            plan_copy = prepare_plan(root, args.plan, args.plan_sha256, tmp)
            plan_sha = args.plan_sha256.lower()
        command = terraform_command(args, plan_copy)
        if not args.confirm_live:
            print(f"DRY RUN ({args.operation}); no AWS call made and Terraform not run.")
            print(f"  account={args.expected_account_id} role={TERRAFORM_ROLE} root={root.name}")
            if plan_sha:
                print("  saved plan SHA-256 and archive structure verified")
                print("  plan variables are verified with terraform show at --confirm-live")
            print("  re-run with --confirm-live after approval.")
            return EXIT_OK

        creds = load_credentials(env, args.operation, now)
        try:
            identity = verify_assumed_role(
                sts_factory(creds), account_id=args.expected_account_id, role_name=TERRAFORM_ROLE
            )
        except IdentityGuardError as exc:
            raise RefusedError(str(exc)) from None
        child_env = build_environment(env, creds, tmp)
        secrets = creds.secrets()

        direction: str | None = None
        if plan_copy is not None:
            direction = inspect_saved_plan(
                runner,
                plan_copy,
                root,
                child_env,
                account_id=args.expected_account_id,
                direction=expected_direction,
            )
        creds.require_lifetime(args.operation, now())  # still enough time after the checks
        result = runner(command, root, child_env)

        unverified: str | None = None
        if args.operation != "apply" and result.returncode == 0 and (root / args.out).is_file():
            try:
                direction = inspect_saved_plan(
                    runner,
                    root / args.out,
                    root,
                    child_env,
                    account_id=args.expected_account_id,
                    direction=expected_direction,
                )
            except PlanVerificationError as exc:
                unverified = str(exc)
            else:
                plan_sha = sha256_of(root / args.out)

    for stream in (result.stdout, result.stderr):
        if stream:
            print(scrub(stream, secrets).rstrip())
    if unverified is not None:
        print(f"plan failed structural verification: {unverified}; do not apply it")
    elif plan_sha is not None and args.operation != "apply":
        print(f"plan_verified={direction}")
        print(f"plan_sha256={plan_sha}")
    if args.record:
        _write_record(
            args.record,
            {
                "operation": args.operation,
                "role": identity["role"],
                "account_verified": identity["account_verified"],
                "plan_sha256": plan_sha,
                "plan_direction": direction,
                "plan_verified": direction is not None and unverified is None,
                "terraform_exit_code": result.returncode,
                "started_utc": started,
                "finished_utc": now().isoformat(timespec="seconds"),
            },
            secrets,
        )
    status = "ok" if result.returncode == 0 else "terraform failed"
    print(f"{args.operation}: {status} (exit {result.returncode})")
    if unverified is not None:
        return EXIT_PLAN_UNVERIFIED
    return EXIT_OK if result.returncode == 0 else EXIT_TERRAFORM_FAILED


def main(
    argv: list[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    sts_factory: StsFactory | None = None,
    runner: Runner | None = None,
    now: Callable[[], datetime] | None = None,
    root: Path = EVAL_ROOT,
) -> int:
    try:
        return _execute(
            argv,
            env=os.environ if env is None else env,
            sts_factory=sts_factory or default_sts_factory,
            runner=runner or subprocess_runner,
            now=now or (lambda: datetime.now(UTC)),
            root=root,
        )
    except RefusedError as exc:
        print(f"refused: {exc}")
        return EXIT_REFUSED
