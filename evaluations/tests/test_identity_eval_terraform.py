"""Offline tests for the M8.5 identity-eval Terraform wrapper.

No AWS call, no Terraform execution: STS and the subprocess runner are injected fakes.
Credential-shaped literals are assembled at runtime so no key-like string is in source.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError

from evaluations.live import terraform_runner as tr
from evaluations.live.aws_identity import IdentityGuardError, verify_assumed_role

REPO_ROOT = Path(__file__).resolve().parents[2]
ACCOUNT = "111122223333"
OTHER_ACCOUNT = "999988887777"
ROLE = tr.TERRAFORM_ROLE
KEY = "ASIA" + "Q" * 16
SECRET = "fake-secret-" + "k" * 24
TOKEN = "fake-session-token-" + "t" * 24
NOW = datetime(2026, 11, 4, 22, 0, tzinfo=UTC)
SECRETS = (KEY, SECRET, TOKEN)


class FakeSts:
    def __init__(
        self,
        arn: str | None = None,
        account: str = ACCOUNT,
        error: Exception | None = None,
        on_call: Any = None,
    ) -> None:
        self.arn = arn or f"arn:aws:sts::{account}:assumed-role/{ROLE}/synthetic-session"
        self.account = account
        self.error = error
        self.on_call = on_call
        self.calls = 0

    def get_caller_identity(self) -> dict[str, Any]:
        self.calls += 1
        if self.on_call is not None:
            self.on_call()
        if self.error is not None:
            raise self.error
        return {
            "UserId": "AROASYNTHETIC:synthetic-session",
            "Account": self.account,
            "Arn": self.arn,
        }


class StsFactory:
    def __init__(self, sts: FakeSts | None = None) -> None:
        self.sts = sts or FakeSts()
        self.created: list[tr.Credentials] = []

    def __call__(self, creds: tr.Credentials) -> FakeSts:
        self.created.append(creds)
        return self.sts


def plan_json(
    account: str = ACCOUNT, kind: str = "create", expires_on: str = "2026-12-01"
) -> dict[str, Any]:
    """A ``terraform show -json`` document shaped like the real plan of the identity-eval root."""
    tags = {
        "Environment": "identity-eval",
        "Ephemeral": "true",
        "ExpiresOn": expires_on,
        "ManagedBy": "terraform",
        "Milestone": "M8.5",
        "Project": "aws-secure-rag-platform",
    }

    def change(rtype: str, rname: str, **attrs: Any) -> dict[str, Any]:
        actions = {"create": ["create"], "delete": ["delete"]}[kind]
        state = (
            {"before": None, "after": attrs}
            if kind == "create"
            else {"before": attrs, "after": None}
        )
        return {
            "address": f"{rtype}.{rname}",
            "mode": "managed",
            "type": rtype,
            "name": rname,
            "provider_name": tr.AWS_PROVIDER,
            "change": {"actions": actions, **state},
        }

    changes = [
        change(
            "aws_cognito_user_pool",
            "eval",
            name="rag-identity-eval-m85-pool",
            deletion_protection="INACTIVE",
            tags_all=dict(tags),
        )
    ]
    changes += [change("aws_cognito_user_group", f"eval{i}", name=f"group-{i}") for i in range(6)]
    changes += [
        change("aws_cognito_user_pool_client", client, generate_secret=False)
        for client in ("app", "other")
    ]
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.8",
        "errored": False,
        "applyable": True,
        "complete": True,
        "variables": {
            "aws_region": {"value": "us-east-1"},
            "expected_account_id": {"value": account},
            "expires_on": {"value": expires_on},
        },
        "resource_changes": changes,
        "configuration": {
            "provider_config": {
                "aws": {
                    "name": "aws",
                    "full_name": tr.AWS_PROVIDER,
                    "expressions": {
                        "allowed_account_ids": {"references": ["var.expected_account_id"]},
                        "default_tags": [{"tags": {"references": ["var.expires_on"]}}],
                        "region": {"references": ["var.aws_region"]},
                    },
                }
            },
            "root_module": {
                "resources": [
                    {"mode": "managed", "type": rtype, "name": "x"}
                    for rtype in tr.EXPECTED_RESOURCES
                ]
            },
        },
    }


def make_plan(
    directory: Path,
    name: str,
    account: str = ACCOUNT,
    entries: dict[str, bytes | None] | None = None,
) -> Path:
    """A structurally valid saved plan built from the config and lock file in ``directory``."""
    files: dict[str, bytes | None] = {
        "tfplan": f"synthetic plan expected_account_id={account}".encode(),
        "tfstate": b"{}",
        "tfstate-prev": b"{}",
        "tfconfig/modules.json": json.dumps([{"Key": "", "Dir": "."}]).encode(),
        ".terraform.lock.hcl": (directory / ".terraform.lock.hcl").read_bytes(),
    }
    for source in sorted(directory.glob("*.tf")):
        files[f"tfconfig/m-/{source.name}"] = source.read_bytes()
    files.update(entries or {})
    path = directory / name
    with zipfile.ZipFile(path, "w") as archive:
        for entry, data in files.items():
            if data is not None:
                archive.writestr(entry, data)
    return path


class FakeRunner:
    """Records every Terraform invocation; ``show`` returns a synthetic plan document."""

    def __init__(
        self,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
        *,
        show_kind: str | None = None,
        show_account: str = ACCOUNT,
        show_rc: int = 0,
        show_stdout: str | None = None,
        show_mutate: Any = None,
    ) -> None:
        self.result = tr.RunResult(returncode, stdout, stderr)
        self.calls: list[dict[str, Any]] = []
        self.show_kind = show_kind
        self.show_account = show_account
        self.show_rc = show_rc
        self.show_stdout = show_stdout
        self.show_mutate = show_mutate
        self.destroying = False

    @property
    def verbs(self) -> list[str]:
        return [call["argv"][1] for call in self.calls]

    def __call__(self, argv: list[str], cwd: Path, env: Any) -> tr.RunResult:
        config_file = Path(env["AWS_CONFIG_FILE"])
        credentials_file = Path(env["AWS_SHARED_CREDENTIALS_FILE"])
        self.calls.append(
            {
                "argv": list(argv),
                "cwd": cwd,
                "env": dict(env),
                "config_size": config_file.stat().st_size,
                "credentials_size": credentials_file.stat().st_size,
                "cli_config_size": Path(env["TF_CLI_CONFIG_FILE"]).stat().st_size,
                "plan_arg_exists": (
                    Path(argv[-1]).is_file() if argv[1] in ("apply", "show") else None
                ),
            }
        )
        if argv[1] == "show":
            return self._show()
        self.destroying = "-destroy" in argv
        for arg in argv:
            if arg.startswith("-out=") and self.result.returncode == 0:
                make_plan(cwd, arg.removeprefix("-out="))
        return self.result

    def _show(self) -> tr.RunResult:
        if self.show_rc != 0:
            return tr.RunResult(self.show_rc, self.show_stdout or "", "Error: cannot read the plan")
        if self.show_stdout is not None:
            return tr.RunResult(0, self.show_stdout, "")
        kind = self.show_kind or ("delete" if self.destroying else "create")
        document = plan_json(self.show_account, kind)
        if self.show_mutate is not None:
            self.show_mutate(document)
        return tr.RunResult(0, json.dumps(document), "")


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    destination = tmp_path / "identity-eval"
    destination.mkdir()
    for source in (tr.EVAL_ROOT).glob("*.tf"):
        shutil.copy(source, destination / source.name)
    shutil.copy(tr.EVAL_ROOT / ".terraform.lock.hcl", destination / ".terraform.lock.hcl")
    return destination


def iso(moment: datetime) -> str:
    return moment.isoformat()


def good_env(**overrides: str | None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "AWS_ACCESS_KEY_ID": KEY,
        "AWS_SECRET_ACCESS_KEY": SECRET,
        "AWS_SESSION_TOKEN": TOKEN,
        "AWS_CREDENTIAL_EXPIRATION": iso(NOW + timedelta(hours=1)),
        # Inherited settings that must not reach Terraform:
        "AWS_PROFILE": "default",
        "AWS_SHARED_CREDENTIALS_FILE": "C:/Users/someone/.aws/credentials",
        "AWS_CONFIG_FILE": "C:/Users/someone/.aws/config",
        "AWS_ENDPOINT_URL": "http://localhost:4566",
        "TF_VAR_expected_account_id": "000000000000",
        "TF_CLI_ARGS": "-target=aws_cognito_user_pool.eval",
        "TF_WORKSPACE": "other",
        "TF_CLI_CONFIG_FILE": "C:/Users/someone/terraform.rc",
    }
    for name, value in overrides.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


def plan_args(*extra: str, out: str = "new.tfplan", account: str = ACCOUNT) -> list[str]:
    return [
        "plan",
        "--expected-account-id",
        account,
        "--expires-on",
        "2026-12-01",
        "--out",
        out,
        *extra,
    ]


def apply_args(plan: str, sha: str, *extra: str, account: str = ACCOUNT) -> list[str]:
    return [
        "apply",
        "--expected-account-id",
        account,
        "--plan",
        plan,
        "--plan-sha256",
        sha,
        *extra,
    ]


def run_cli(
    argv: list[str],
    root: Path,
    *,
    env: dict[str, str] | None = None,
    factory: StsFactory | None = None,
    runner: FakeRunner | None = None,
    now: Any = None,
) -> tuple[int, StsFactory, FakeRunner]:
    factory = factory or StsFactory()
    runner = runner or FakeRunner()
    code = tr.main(
        argv,
        env=good_env() if env is None else env,
        sts_factory=factory,
        runner=runner,
        now=now or (lambda: NOW),
        root=root,
    )
    return code, factory, runner


def saved_plan(root: Path, name: str = "saved.tfplan", account: str = ACCOUNT) -> tuple[str, str]:
    path = make_plan(root, name, account)
    return name, tr.sha256_of(path)


# --- allowed operations ------------------------------------------------------------------


def test_plan_runs_pinned_command_and_reports_the_plan_hash(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, factory, runner = run_cli(plan_args("--confirm-live"), root)
    assert code == 0
    assert runner.verbs == ["plan", "show"]  # plan, then a read-only inspection of its output
    call = runner.calls[0]
    assert call["argv"] == [
        "terraform",
        "plan",
        "-input=false",
        "-lock=true",
        "-no-color",
        "-out=new.tfplan",
        "-var",
        f"expected_account_id={ACCOUNT}",
        "-var",
        "expires_on=2026-12-01",
    ]
    assert call["cwd"] == root
    assert runner.calls[1]["argv"] == [
        "terraform",
        "show",
        "-json",
        "-no-color",
        str(root / "new.tfplan"),
    ]
    out = capsys.readouterr().out
    assert f"plan_sha256={tr.sha256_of(root / 'new.tfplan')}" in out
    assert "plan_verified=create" in out
    assert factory.sts.calls == 1


def test_plan_destroy_adds_only_the_destroy_flag(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["plan-destroy", *plan_args("--confirm-live")[1:]]
    code, _, runner = run_cli(argv, root)
    assert code == 0 and runner.verbs == ["plan", "show"]
    command = runner.calls[0]["argv"]
    assert command[:3] == ["terraform", "plan", "-input=false"] and "-destroy" in command
    assert command.index("-destroy") == 5
    assert "plan_verified=delete" in capsys.readouterr().out


def test_apply_applies_a_verified_private_copy_of_the_plan(root: Path) -> None:
    name, sha = saved_plan(root)
    code, _, runner = run_cli(apply_args(name, sha, "--confirm-live"), root)
    assert code == 0
    assert runner.verbs == ["show", "apply"]  # inspected first, applied only afterwards
    inspected, call = runner.calls
    assert inspected["argv"][:4] == ["terraform", "show", "-json", "-no-color"]
    assert call["argv"][:5] == ["terraform", "apply", "-input=false", "-lock=true", "-no-color"]
    applied = Path(call["argv"][-1])
    assert applied.name == name and applied.parent != root  # the verified copy, not the original
    assert inspected["argv"][-1] == call["argv"][-1]  # the very file that was inspected
    assert call["plan_arg_exists"] is True and inspected["plan_arg_exists"] is True
    assert "-auto-approve" not in call["argv"] and "-target" not in " ".join(call["argv"])


def test_apply_accepts_an_uppercase_hash(root: Path) -> None:
    name, sha = saved_plan(root)
    assert run_cli(apply_args(name, sha.upper(), "--confirm-live"), root)[0] == 0


def test_apply_accepts_a_destroy_plan_and_a_create_plan(root: Path) -> None:
    name, sha = saved_plan(root)
    for kind in ("create", "delete"):
        runner = FakeRunner(show_kind=kind)
        code, _, _ = run_cli(apply_args(name, sha, "--confirm-live"), root, runner=runner)
        assert code == 0 and runner.verbs == ["show", "apply"]


def test_dry_run_contacts_nothing_and_runs_nothing(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    name, sha = saved_plan(root)
    for argv in (plan_args(), ["plan-destroy", *plan_args()[1:]], apply_args(name, sha)):
        code, factory, runner = run_cli(argv, root, env={})
        assert code == 0 and factory.created == [] and runner.calls == []
    assert "DRY RUN" in capsys.readouterr().out


def test_dry_run_still_verifies_the_plan_hash_and_structure(root: Path) -> None:
    name, _ = saved_plan(root)
    code, factory, runner = run_cli(apply_args(name, "0" * 64), root, env={})
    assert code == 4 and factory.created == [] and runner.calls == []
    make_plan(root, "odd.tfplan", entries={"evil.sh": b"x"})
    sha = tr.sha256_of(root / "odd.tfplan")
    code, factory, runner = run_cli(apply_args("odd.tfplan", sha), root, env={})
    assert code == 4 and factory.created == [] and runner.calls == []


# --- saved-plan integrity ------------------------------------------------------------------


def test_modified_saved_plan_is_rejected(root: Path) -> None:
    name, sha = saved_plan(root)
    with (root / name).open("ab") as handle:
        handle.write(b"tampered")
    code, factory, runner = run_cli(apply_args(name, sha, "--confirm-live"), root)
    assert code == 4 and runner.calls == [] and factory.created == []


def test_replaced_saved_plan_is_rejected(root: Path) -> None:
    name, sha = saved_plan(root)
    make_plan(root, name, OTHER_ACCOUNT)
    code, _, runner = run_cli(apply_args(name, sha, "--confirm-live"), root)
    assert code == 4 and runner.calls == []


def test_plan_for_another_account_is_rejected_by_its_variables_even_with_a_matching_hash(
    root: Path,
) -> None:
    name, sha = saved_plan(root)
    runner = FakeRunner(show_account=OTHER_ACCOUNT)
    code, _, runner = run_cli(apply_args(name, sha, "--confirm-live"), root, runner=runner)
    assert code == 4 and runner.verbs == ["show"]  # inspected, never applied


@pytest.mark.parametrize("content", [b"", b"not a zip archive"])
def test_non_plan_file_is_rejected(root: Path, content: bytes) -> None:
    (root / "junk.tfplan").write_bytes(content)
    sha = tr.sha256_of(root / "junk.tfplan")
    code, _, runner = run_cli(apply_args("junk.tfplan", sha, "--confirm-live"), root)
    assert code == 4 and runner.calls == []


def test_zip_without_a_plan_entry_is_rejected(root: Path) -> None:
    with zipfile.ZipFile(root / "odd.tfplan", "w") as archive:
        archive.writestr("other", ACCOUNT)
    sha = tr.sha256_of(root / "odd.tfplan")
    assert run_cli(apply_args("odd.tfplan", sha, "--confirm-live"), root)[0] == 4


@pytest.mark.parametrize(
    "plan",
    [
        "missing.tfplan",
        "../escape.tfplan",
        "sub/x.tfplan",
        "x.txt",
        "..\\x.tfplan",
        "a b.tfplan",
        "",
    ],
)
def test_apply_only_accepts_a_plain_existing_plan_name(root: Path, plan: str) -> None:
    code, factory, runner = run_cli(apply_args(plan, "0" * 64, "--confirm-live"), root)
    assert code == 4 and runner.calls == [] and factory.created == []


@pytest.mark.parametrize("sha", ["", "abc", "g" * 64, "0" * 63, "0" * 65])
def test_apply_requires_a_well_formed_sha256(root: Path, sha: str) -> None:
    name, _ = saved_plan(root)
    code, _, runner = run_cli(apply_args(name, sha, "--confirm-live"), root)
    assert code == 4 and runner.calls == []


def test_existing_plan_is_never_overwritten(root: Path) -> None:
    saved_plan(root, "new.tfplan")
    before = tr.sha256_of(root / "new.tfplan")
    code, _, runner = run_cli(plan_args("--confirm-live"), root)
    assert code == 4 and runner.calls == [] and tr.sha256_of(root / "new.tfplan") == before


# --- identity: every operation, including cleanup (destroy) ---------------------------------


def _operations(root: Path) -> dict[str, list[str]]:
    name, sha = saved_plan(root)
    return {
        "plan": plan_args("--confirm-live"),
        "plan-destroy": ["plan-destroy", *plan_args("--confirm-live", out="destroy.tfplan")[1:]],
        "apply": apply_args(name, sha, "--confirm-live"),
    }


BAD_CALLERS: dict[str, dict[str, Any]] = {
    "wrong_account": {"account": OTHER_ACCOUNT},
    "arn_in_other_account": {
        "arn": f"arn:aws:sts::{OTHER_ACCOUNT}:assumed-role/{ROLE}/synthetic-session"
    },
    "harness_role": {
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/rag-eval-harness/synthetic-session"
    },
    "similar_role": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}-admin/synthetic-session"},
    "iam_user": {"arn": f"arn:aws:iam::{ACCOUNT}:user/terraform-user"},
    "root": {"arn": f"arn:aws:iam::{ACCOUNT}:root"},
    "federated": {"arn": f"arn:aws:sts::{ACCOUNT}:federated-user/someone"},
    "sso_admin_role": {
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/AWSReservedSSO_AdministratorAccess_x/me"
    },
    "other_partition": {"arn": f"arn:aws-cn:sts::{ACCOUNT}:assumed-role/{ROLE}/synthetic-session"},
    "extra_segment": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/synthetic-session/more"},
    "malformed": {"arn": "not-an-arn"},
    "expired_token": {
        "error": ClientError({"Error": {"Code": "ExpiredToken"}}, "GetCallerIdentity")
    },
    "unreachable": {"error": OSError("network down")},
    "access_denied": {
        "error": ClientError({"Error": {"Code": "AccessDenied"}}, "GetCallerIdentity")
    },
}


@pytest.mark.parametrize("operation", ["plan", "plan-destroy", "apply"])
@pytest.mark.parametrize("kind", sorted(BAD_CALLERS))
def test_terraform_is_never_invoked_after_a_failed_identity_check(
    root: Path, operation: str, kind: str, capsys: pytest.CaptureFixture[str]
) -> None:
    factory = StsFactory(FakeSts(**BAD_CALLERS[kind]))
    code, _, runner = run_cli(_operations(root)[operation], root, factory=factory)
    assert code == 4 and runner.calls == []
    assert factory.sts.calls == 1
    output = capsys.readouterr()
    text = output.out + output.err
    assert OTHER_ACCOUNT not in text and ACCOUNT not in text and "synthetic-session" not in text
    assert "terraform-user" not in text and "AROA" not in text


def test_malformed_identity_response_fails_closed(root: Path) -> None:
    class Broken:
        def get_caller_identity(self) -> dict[str, Any]:
            return {"Account": ACCOUNT}

    class Typed:
        def get_caller_identity(self) -> dict[str, Any]:
            return {"Account": ACCOUNT, "Arn": None}

    for sts in (Broken(), Typed()):
        code, _, runner = run_cli(plan_args("--confirm-live"), root, factory=StsFactory(sts))  # type: ignore[arg-type]
        assert code == 4 and runner.calls == []


def test_the_wrapper_and_harness_roles_are_not_interchangeable() -> None:
    harness_sts = FakeSts(arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/rag-eval-harness/synthetic")
    with pytest.raises(IdentityGuardError):
        verify_assumed_role(harness_sts, account_id=ACCOUNT, role_name=ROLE)
    verify_assumed_role(FakeSts(), account_id=ACCOUNT, role_name=ROLE)


# --- credentials: missing, long-lived, expired ----------------------------------------------


@pytest.mark.parametrize("name", tr.CREDENTIAL_VARS)
@pytest.mark.parametrize("value", [None, "", "   "])
def test_missing_or_blank_credentials_fail_closed(root: Path, name: str, value: str | None) -> None:
    code, factory, runner = run_cli(
        plan_args("--confirm-live"), root, env=good_env(**{name: value})
    )
    assert code == 4 and factory.created == [] and runner.calls == []


def test_inherited_profile_alone_is_never_enough(root: Path) -> None:
    env = {k: v for k, v in good_env().items() if k not in tr.CREDENTIAL_VARS}
    code, factory, runner = run_cli(plan_args("--confirm-live"), root, env=env)
    assert code == 4 and factory.created == [] and runner.calls == []


@pytest.mark.parametrize(
    "key_id",
    ["AKIA" + "Q" * 16, "ASIA" + "Q" * 15, "ASIA" + "q" * 16, "asia" + "Q" * 16, "Q" * 20],
)
def test_long_lived_or_malformed_access_key_ids_are_refused(root: Path, key_id: str) -> None:
    code, factory, runner = run_cli(
        plan_args("--confirm-live"), root, env=good_env(AWS_ACCESS_KEY_ID=key_id)
    )
    assert code == 4 and factory.created == [] and runner.calls == []


OPERATIONS = ("plan", "plan-destroy", "apply")


def _argv_for(root: Path, operation: str) -> list[str]:
    for leftover in ("new.tfplan", "destroy.tfplan"):  # plans are never overwritten
        (root / leftover).unlink(missing_ok=True)
    return _operations(root)[operation]


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("value", [None, "", "   "])
def test_a_missing_expiration_is_refused_for_every_operation(
    root: Path, operation: str, value: str | None
) -> None:
    env = good_env(AWS_CREDENTIAL_EXPIRATION=value)
    code, factory, runner = run_cli(_argv_for(root, operation), root, env=env)
    assert code == 4 and factory.created == [] and runner.calls == []


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(
    "expiration",
    [
        "tomorrow",
        "2026-13-45T99:00:00Z",
        "not-a-time",
        "1730761200",  # epoch seconds
        "2026-11-04",  # a date alone is naive
        "2026-11-04T23:30:00",  # naive: no timezone
        "2026-11-04 23:30:00",
        "T23:30:00Z",
    ],
)
def test_a_malformed_or_timezone_free_expiration_is_refused(
    root: Path, operation: str, expiration: str
) -> None:
    env = good_env(AWS_CREDENTIAL_EXPIRATION=expiration)
    code, factory, runner = run_cli(_argv_for(root, operation), root, env=env)
    assert code == 4 and factory.created == [] and runner.calls == []


@pytest.mark.parametrize(
    ("operation", "minimum_minutes"), [("plan", 20), ("plan-destroy", 20), ("apply", 30)]
)
def test_the_remaining_lifetime_must_cover_the_operation(
    root: Path, operation: str, minimum_minutes: int
) -> None:
    just_short = NOW + timedelta(minutes=minimum_minutes) - timedelta(seconds=1)
    exactly = NOW + timedelta(minutes=minimum_minutes)
    for expiration, accepted in ((just_short, False), (exactly, True)):
        env = good_env(AWS_CREDENTIAL_EXPIRATION=iso(expiration))
        code, factory, runner = run_cli(_argv_for(root, operation), root, env=env)
        assert (code == 0) is accepted
        assert bool(factory.created) is accepted and bool(runner.calls) is accepted


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(
    "offset", [timedelta(seconds=-1), timedelta(minutes=-1), timedelta(hours=-5), timedelta(0)]
)
def test_expired_credentials_are_refused_before_any_aws_call(
    root: Path, operation: str, offset: timedelta
) -> None:
    env = good_env(AWS_CREDENTIAL_EXPIRATION=iso(NOW + offset))
    code, factory, runner = run_cli(_argv_for(root, operation), root, env=env)
    assert code == 4 and factory.created == [] and runner.calls == []


@pytest.mark.parametrize("operation", OPERATIONS)
def test_an_implausibly_distant_expiration_is_refused(root: Path, operation: str) -> None:
    for expiration, accepted in (
        (NOW + timedelta(hours=12), True),
        (NOW + timedelta(hours=12, minutes=5), True),
        (NOW + timedelta(hours=12, minutes=5, seconds=1), False),
        (NOW + timedelta(days=365), False),
        (NOW + timedelta(days=36500), False),
    ):
        env = good_env(AWS_CREDENTIAL_EXPIRATION=iso(expiration))
        code, factory, runner = run_cli(_argv_for(root, operation), root, env=env)
        assert (code == 0) is accepted and bool(factory.created) is accepted


@pytest.mark.parametrize(
    "expiration",
    [
        "2026-11-04T23:05:00+00:00",
        "2026-11-04T23:05:00.123456+00:00",  # what `aws configure export-credentials` prints
        "2026-11-04T23:05:00Z",
        "2026-11-05T04:05:00+05:00",  # same instant, other offset (21:05 UTC is too soon)
        "2026-11-04T18:05:00-05:00",  # 23:05 UTC
    ],
)
def test_iso_expirations_with_a_timezone_are_compared_in_utc(root: Path, expiration: str) -> None:
    accepted = datetime.fromisoformat(expiration).astimezone(UTC) >= NOW + timedelta(minutes=20)
    code, factory, runner = run_cli(
        plan_args("--confirm-live"), root, env=good_env(AWS_CREDENTIAL_EXPIRATION=expiration)
    )
    assert (code == 0) is accepted and bool(factory.created) is accepted


@pytest.mark.parametrize(("operation", "expected_verbs"), [("plan", []), ("apply", ["show"])])
def test_lifetime_is_checked_again_after_the_slow_checks(
    root: Path, operation: str, expected_verbs: list[str]
) -> None:
    clock = {"now": NOW}
    sts = FakeSts(on_call=lambda: clock.update(now=clock["now"] + timedelta(minutes=2)))
    minimum = {"plan": 20, "apply": 30}[operation]
    env = good_env(AWS_CREDENTIAL_EXPIRATION=iso(NOW + timedelta(minutes=minimum, seconds=30)))
    code, factory, runner = run_cli(
        _argv_for(root, operation),
        root,
        env=env,
        factory=StsFactory(sts),
        now=lambda: clock["now"],
    )
    # accepted at load time, but too little life remained once STS had been called
    assert code == 4 and len(factory.created) == 1
    assert runner.verbs == expected_verbs  # never reached the plan/apply itself


def test_the_expiration_variable_is_not_passed_to_terraform(root: Path) -> None:
    code, _, runner = run_cli(plan_args("--confirm-live"), root)
    assert code == 0
    assert all("AWS_CREDENTIAL_EXPIRATION" not in call["env"] for call in runner.calls)


def test_identity_center_style_sessions_are_accepted_when_the_role_matches(root: Path) -> None:
    arn = f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/first.last@example.com"
    env = good_env(AWS_CREDENTIAL_EXPIRATION="2026-11-04T23:30:00.250000+00:00")
    code, _, runner = run_cli(
        plan_args("--confirm-live"), root, env=env, factory=StsFactory(FakeSts(arn=arn))
    )
    assert code == 0 and runner.verbs == ["plan", "show"]


# --- the Terraform process environment -------------------------------------------------------


def test_child_environment_is_rebuilt_without_inherited_credentials_or_settings(root: Path) -> None:
    code, factory, runner = run_cli(plan_args("--confirm-live"), root)
    assert code == 0
    call = runner.calls[0]
    env = call["env"]
    assert "AWS_PROFILE" not in env and "AWS_ENDPOINT_URL" not in env
    assert not any(k.startswith("TF_VAR_") for k in env)
    assert "TF_CLI_ARGS" not in env and "TF_WORKSPACE" not in env
    assert (env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"]) == (KEY, SECRET)
    assert env["AWS_SESSION_TOKEN"] == TOKEN
    assert env["AWS_REGION"] == env["AWS_DEFAULT_REGION"] == "us-east-1"
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"
    assert env["TF_IN_AUTOMATION"] == "1" and env["TF_INPUT"] == "0"
    assert env["PATH"] == os.environ.get("PATH", "")
    # the shared files exist but are empty and private, never the user's real ones
    assert call["config_size"] == 0 and call["credentials_size"] == 0
    # a user-level Terraform CLI config (dev_overrides, mirrors) is replaced by an empty one
    assert call["cli_config_size"] == 0
    assert env["TF_CLI_CONFIG_FILE"] != "C:/Users/someone/terraform.rc"
    assert ".aws" not in env["AWS_SHARED_CREDENTIALS_FILE"] + env["AWS_CONFIG_FILE"]
    assert not Path(env["AWS_CONFIG_FILE"]).exists()  # removed after the run
    # STS saw the same credentials Terraform did
    assert factory.created[0].secrets() == SECRETS


def test_sts_client_is_built_from_explicit_credentials_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boto3

    captured: dict[str, Any] = {}

    def fake_client(service: str, **kwargs: Any) -> object:
        captured.update(service=service, **kwargs)
        return object()

    monkeypatch.setattr(boto3, "client", fake_client)
    tr.default_sts_factory(tr.Credentials(KEY, SECRET, TOKEN))
    assert captured["service"] == "sts" and captured["region_name"] == "us-east-1"
    assert (captured["aws_access_key_id"], captured["aws_secret_access_key"]) == (KEY, SECRET)
    assert captured["aws_session_token"] == TOKEN


def test_credentials_repr_hides_every_value() -> None:
    text = repr(tr.Credentials(KEY, SECRET, TOKEN))
    assert not any(secret in text for secret in SECRETS)


# --- terraform root safeguards -------------------------------------------------------------------


def test_the_real_identity_eval_root_passes_the_static_checks() -> None:
    tr.check_terraform_root(tr.EVAL_ROOT)


def _append(root: Path, name: str, text: str) -> None:
    with (root / name).open("a", encoding="utf-8") as handle:
        handle.write(text)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: _append(
            r, "versions.tf", '\nprovider "aws" {\n  alias = "x"\n  profile = "default"\n}\n'
        ),
        lambda r: _append(r, "versions.tf", '\nprovider "aws" {\n  access_key = "x"\n}\n'),
        lambda r: _append(r, "versions.tf", '\nprovider "aws" {\n  token = "x"\n}\n'),
        lambda r: _append(r, "versions.tf", '\nprovider "aws" {\n  assume_role {\n  }\n}\n'),
        lambda r: _append(r, "versions.tf", '\nprovider "aws" {\n  endpoints {\n  }\n}\n'),
        lambda r: _append(
            r, "versions.tf", '\nprovider "aws" {\n  skip_requesting_account_id = true\n}\n'
        ),
        lambda r: _append(
            r, "versions.tf", '\nprovider "aws" {\n  shared_credentials_files = ["x"]\n}\n'
        ),
        lambda r: (r / "versions.tf").write_text(
            (r / "versions.tf").read_text().replace("allowed_account_ids", "ignored_account_ids")
        ),
        lambda r: (r / "versions.tf").write_text(
            (r / "versions.tf").read_text().replace("[var.expected_account_id]", '["111122223333"]')
        ),
        lambda r: (r / "override.tf").write_text("# empty\n"),
        lambda r: (r / "aws_override.tf").write_text("# empty\n"),
        lambda r: (r / "terraform.tfvars").write_text("expected_account_id = 1\n"),
        lambda r: (r / "extra.auto.tfvars").write_text("expires_on = 1\n"),
        lambda r: (r / "extra.auto.tfvars.json").write_text("{}"),
        lambda r: _append(r, "versions.tf", '\nmodule "other" {\n  source = "./elsewhere"\n}\n'),
    ],
    ids=[
        "profile",
        "access_key",
        "token",
        "assume_role",
        "endpoints",
        "skip_account_id",
        "shared_credentials",
        "no_allowed_ids",
        "hardcoded_ids",
        "override",
        "named_override",
        "tfvars",
        "auto_tfvars",
        "auto_tfvars_json",
        "module_block",
    ],
)
def test_a_weakened_terraform_root_is_refused_before_any_aws_call(root: Path, mutate: Any) -> None:
    mutate(root)
    code, factory, runner = run_cli(plan_args("--confirm-live"), root)
    assert code == 4 and factory.created == [] and runner.calls == []


def test_commented_out_settings_do_not_trip_the_check(root: Path) -> None:
    _append(
        root, "versions.tf", '\n# profile = "default"\n// access_key = "x"\n/* token = "x" */\n'
    )
    assert run_cli(plan_args("--confirm-live"), root)[0] == 0


def test_example_tfvars_and_readme_are_allowed(root: Path) -> None:
    (root / "terraform.tfvars.example").write_text("expected_account_id = 123456789012\n")
    (root / "README.md").write_text("docs\n")
    assert run_cli(plan_args("--confirm-live"), root)[0] == 0


# --- no other operation or argument is accepted --------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["destroy", "--expected-account-id", ACCOUNT],
        ["init"],
        ["import"],
        ["state", "rm"],
        ["console"],
        ["force-unlock"],
        ["apply-auto"],
        [],
        plan_args("--confirm-live", "-target=aws_cognito_user_pool.eval"),
        plan_args("--confirm-live", "-auto-approve"),
        plan_args("--confirm-live", "--auto-approve"),
        plan_args("--confirm-live", "-var-file=x.tfvars"),
        plan_args("--confirm-live", "-refresh=false"),
        plan_args("--confirm-live", "--", "-lock=false"),
        ["plan", "--expected-acc", ACCOUNT, "--expires-on", "2026-12-01", "--out", "n.tfplan"],
        ["plan", "--expires-on", "2026-12-01", "--out", "n.tfplan"],
        ["plan", "--expected-account-id", ACCOUNT, "--out", "n.tfplan"],
        ["plan", "--expected-account-id", ACCOUNT, "--expires-on", "2026-12-01"],
        plan_args("--confirm-live", account="12345678901"),
        plan_args("--confirm-live", account="1234567890123"),
        plan_args("--confirm-live", account="11112222333a"),
        plan_args("--confirm-live", account=""),
        plan_args("--confirm-live", out="../n.tfplan"),
        plan_args("--confirm-live", out="n.txt"),
        plan_args("--confirm-live", out="sub/n.tfplan"),
        [
            "plan",
            "--expected-account-id",
            ACCOUNT,
            "--expires-on",
            "2026-13-01",
            "--out",
            "n.tfplan",
        ],
        ["plan", "--expected-account-id", ACCOUNT, "--expires-on", "2026-1-1", "--out", "n.tfplan"],
        ["plan", "--expected-account-id", ACCOUNT, "--expires-on", "soon", "--out", "n.tfplan"],
    ],
)
def test_unapproved_operations_and_arguments_are_refused(root: Path, argv: list[str]) -> None:
    code, factory, runner = run_cli(argv, root)
    assert code == 4 and factory.created == [] and runner.calls == []


# --- malformed saved plans: structure of the archive and its embedded configuration -------------


def _read(root: Path, name: str) -> bytes:
    return (root / name).read_bytes()


def _modules(value: Any) -> bytes:
    return value if isinstance(value, bytes) else json.dumps(value).encode()


def _archive_cases(root: Path) -> dict[str, dict[str, bytes | None]]:
    versions = _read(root, "versions.tf")
    lock = _read(root, ".terraform.lock.hcl")
    return {
        "extra_entry": {"evil.sh": b"x"},
        "traversal_entry": {"../evil.tf": b"x"},
        "absolute_entry": {"/etc/evil": b"x"},
        "nested_config": {"tfconfig/m-/sub/x.tf": b"x"},
        "non_tf_config": {"tfconfig/m-/notes.txt": b"x"},
        "child_module_dir": {"tfconfig/m-child/x.tf": b"x"},
        "dotdot_config_name": {"tfconfig/m-/..tf": b"x"},
        "missing_tfplan": {"tfplan": None},
        "missing_lock": {".terraform.lock.hcl": None},
        "missing_modules": {"tfconfig/modules.json": None},
        "empty_tfplan": {"tfplan": b""},
        "two_modules": {
            "tfconfig/modules.json": _modules([{"Key": "", "Dir": "."}, {"Key": "x", "Dir": "x"}])
        },
        "child_module_only": {"tfconfig/modules.json": _modules([{"Key": "x", "Dir": "x"}])},
        "modules_wrong_dir": {"tfconfig/modules.json": _modules([{"Key": "", "Dir": "elsewhere"}])},
        "modules_object": {"tfconfig/modules.json": _modules({})},
        "modules_empty_list": {"tfconfig/modules.json": _modules([])},
        "modules_not_json": {"tfconfig/modules.json": b"{not json"},
        "embedded_profile": {
            "tfconfig/m-/versions.tf": versions + b'\nprovider "aws" {\n  profile = "x"\n}\n'
        },
        "embedded_guard_removed": {
            "tfconfig/m-/versions.tf": versions.replace(b"allowed_account_ids", b"ignored_ids")
        },
        "embedded_hardcoded_account": {
            "tfconfig/m-/versions.tf": versions.replace(
                b"[var.expected_account_id]", b'["111122223333"]'
            )
        },
        "embedded_module_block": {
            "tfconfig/m-/versions.tf": versions + b'\nmodule "x" {\n  source = "./x"\n}\n'
        },
        "embedded_extra_file": {"tfconfig/m-/extra.tf": b"# harmless looking"},
        "embedded_missing_file": {"tfconfig/m-/outputs.tf": None},
        "embedded_one_byte_changed": {"tfconfig/m-/cognito.tf": _read(root, "cognito.tf") + b" "},
        "lock_changed": {".terraform.lock.hcl": lock + b"# extra\n"},
        "lock_emptied": {".terraform.lock.hcl": b""},
    }


ARCHIVE_CASES = [
    "extra_entry",
    "traversal_entry",
    "absolute_entry",
    "nested_config",
    "non_tf_config",
    "child_module_dir",
    "dotdot_config_name",
    "missing_tfplan",
    "missing_lock",
    "missing_modules",
    "empty_tfplan",
    "two_modules",
    "child_module_only",
    "modules_wrong_dir",
    "modules_object",
    "modules_empty_list",
    "modules_not_json",
    "embedded_profile",
    "embedded_guard_removed",
    "embedded_hardcoded_account",
    "embedded_module_block",
    "embedded_extra_file",
    "embedded_missing_file",
    "embedded_one_byte_changed",
    "lock_changed",
    "lock_emptied",
]


@pytest.mark.parametrize("case", ARCHIVE_CASES)
def test_a_structurally_malformed_plan_archive_is_refused_before_any_aws_call(
    root: Path, case: str
) -> None:
    entries = _archive_cases(root)[case]
    make_plan(root, "bad.tfplan", entries=entries)
    sha = tr.sha256_of(root / "bad.tfplan")  # the hash matches: only the structure is wrong
    code, factory, runner = run_cli(apply_args("bad.tfplan", sha, "--confirm-live"), root)
    assert code == 4 and factory.created == [] and runner.calls == []


def test_duplicate_entries_are_refused(root: Path) -> None:
    make_plan(root, "dup.tfplan")
    with pytest.warns(UserWarning), zipfile.ZipFile(root / "dup.tfplan", "a") as archive:
        archive.writestr("tfplan", b"a second plan body")
    sha = tr.sha256_of(root / "dup.tfplan")
    code, _, runner = run_cli(apply_args("dup.tfplan", sha, "--confirm-live"), root)
    assert code == 4 and runner.calls == []


def _write_directory(archive: zipfile.ZipFile) -> None:
    archive.writestr("tfconfig/m-/", b"")


def test_encrypted_and_directory_entries_are_refused(root: Path) -> None:
    builders = {"enc.tfplan": _write_flagged, "dir.tfplan": _write_directory}
    for name, build in builders.items():
        make_plan(root, name)
        with zipfile.ZipFile(root / name, "a") as archive:
            build(archive)
        sha = tr.sha256_of(root / name)
        code, _, runner = run_cli(apply_args(name, sha, "--confirm-live"), root)
        assert code == 4 and runner.calls == [], name


def _write_flagged(archive: zipfile.ZipFile) -> None:
    info = zipfile.ZipInfo("tfstate-extra")
    info.flag_bits |= 0x1
    archive.writestr(info, b"x")


def test_a_truncated_archive_is_refused(root: Path) -> None:
    make_plan(root, "cut.tfplan")
    data = (root / "cut.tfplan").read_bytes()
    (root / "cut.tfplan").write_bytes(data[: len(data) // 2])
    sha = tr.sha256_of(root / "cut.tfplan")
    code, _, runner = run_cli(apply_args("cut.tfplan", sha, "--confirm-live"), root)
    assert code == 4 and runner.calls == []


def test_an_oversized_plan_entry_is_refused(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    make_plan(root, "big.tfplan", entries={"tfplan": b"x" * 64})
    sha = tr.sha256_of(root / "big.tfplan")
    monkeypatch.setattr(tr, "MAX_PLAN_BYTES", 32)
    code, _, runner = run_cli(apply_args("big.tfplan", sha, "--confirm-live"), root)
    assert code == 4 and runner.calls == []


def test_a_well_formed_archive_is_accepted_with_crlf_config_and_no_state_entries(
    root: Path,
) -> None:
    crlf = {
        f"tfconfig/m-/{p.name}": p.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        for p in root.glob("*.tf")
    }
    make_plan(root, "ok.tfplan", entries={**crlf, "tfstate": None, "tfstate-prev": None})
    sha = tr.sha256_of(root / "ok.tfplan")
    code, _, runner = run_cli(apply_args("ok.tfplan", sha, "--confirm-live"), root)
    assert code == 0 and runner.verbs == ["show", "apply"]


def test_a_plan_made_from_other_configuration_than_the_reviewed_root_is_refused(
    root: Path,
) -> None:
    name, sha = saved_plan(root)
    with (root / "cognito.tf").open("a", encoding="utf-8") as handle:
        handle.write("\n# edited after the plan was made\n")
    code, factory, runner = run_cli(apply_args(name, sha, "--confirm-live"), root)
    assert code == 4 and factory.created == [] and runner.calls == []


# --- terraform show -json: the plan's variables, provider guard and changes ---------------------


def _set(path: list[str], value: Any) -> Any:
    def mutate(doc: dict[str, Any]) -> None:
        target = doc
        for key in path[:-1]:
            target = target[int(key)] if isinstance(target, list) else target[key]
        if isinstance(target, list):
            target[int(path[-1])] = value
        else:
            target[path[-1]] = value

    return mutate


def _drop(path: list[str]) -> Any:
    def mutate(doc: dict[str, Any]) -> None:
        target = doc
        for key in path[:-1]:
            target = target[int(key)] if isinstance(target, list) else target[key]
        del target[path[-1]]

    return mutate


def _expressions(doc: dict[str, Any]) -> dict[str, Any]:
    expressions: dict[str, Any] = doc["configuration"]["provider_config"]["aws"]["expressions"]
    return expressions


def _tags(doc: dict[str, Any]) -> dict[str, Any]:
    tags: dict[str, Any] = doc["resource_changes"][0]["change"]["after"]["tags_all"]
    return tags


def _compose(*mutators: Any) -> Any:
    def mutate(doc: dict[str, Any]) -> None:
        for mutator in mutators:
            mutator(doc)

    return mutate


def _misleading(doc: dict[str, Any]) -> None:
    """The expected account appears all over the plan except where it counts."""
    doc["variables"]["expected_account_id"]["value"] = OTHER_ACCOUNT
    _tags(doc)["Owner"] = ACCOUNT
    doc["resource_changes"][1]["change"]["after"]["name"] = f"group-{ACCOUNT}"
    doc["output_changes"] = {"issuer": {"after": f"https://example/{ACCOUNT}"}}


def _extra_change(rtype: str) -> Any:
    def mutate(doc: dict[str, Any]) -> None:
        extra = json.loads(json.dumps(doc["resource_changes"][1]))
        extra.update(type=rtype, address=f"{rtype}.extra")
        doc["resource_changes"].append(extra)

    return mutate


def _remove_change(doc: dict[str, Any]) -> None:
    doc["resource_changes"].pop(1)


JSON_CASES: dict[str, Any] = {
    "variable_other_account": _set(["variables", "expected_account_id", "value"], OTHER_ACCOUNT),
    "variable_prefix_match": _set(["variables", "expected_account_id", "value"], ACCOUNT + "0"),
    "variable_suffix_match": _set(["variables", "expected_account_id", "value"], "0" + ACCOUNT),
    "variable_padded": _set(["variables", "expected_account_id", "value"], f" {ACCOUNT} "),
    "variable_as_list": _set(["variables", "expected_account_id", "value"], [ACCOUNT]),
    "variable_as_number": _set(["variables", "expected_account_id", "value"], int(ACCOUNT)),
    "variable_missing": _drop(["variables", "expected_account_id"]),
    "variable_null": _set(["variables", "expected_account_id", "value"], None),
    "extra_variable": _set(["variables", "other"], {"value": ACCOUNT}),
    "region_variable_wrong": _set(["variables", "aws_region", "value"], "us-west-2"),
    "expires_on_not_a_date": _set(["variables", "expires_on", "value"], "soon"),
    "expires_on_unpadded": _set(["variables", "expires_on", "value"], "2026-1-1"),
    "expires_on_missing": _drop(["variables", "expires_on"]),
    "account_only_in_other_fields": _misleading,
    "guard_is_a_constant": lambda d: _expressions(d).update(
        allowed_account_ids={"constant_value": [ACCOUNT]}
    ),
    "guard_other_variable": lambda d: _expressions(d).update(
        allowed_account_ids={"references": ["var.aws_region"]}
    ),
    "guard_mixed_references": lambda d: _expressions(d).update(
        allowed_account_ids={"references": ["var.expected_account_id", "var.aws_region"]}
    ),
    "guard_removed": lambda d: _expressions(d).pop("allowed_account_ids"),
    "provider_profile": lambda d: _expressions(d).update(profile={"constant_value": "default"}),
    "provider_assume_role": lambda d: _expressions(d).update(assume_role=[{"role_arn": {}}]),
    "provider_second_instance": lambda d: d["configuration"]["provider_config"].update(
        {"aws.other": d["configuration"]["provider_config"]["aws"]}
    ),
    "provider_other_source": _set(
        ["configuration", "provider_config", "aws", "full_name"], "registry.terraform.io/evil/aws"
    ),
    "region_hardcoded": lambda d: _expressions(d).update(region={"constant_value": "us-west-2"}),
    "extra_resource_type": _extra_change("aws_iam_role"),
    "extra_known_type": _extra_change("aws_cognito_user_group"),
    "one_resource_short": _remove_change,
    "data_source_change": _set(["resource_changes", "0", "mode"], "data"),
    "other_provider": _set(["resource_changes", "1", "provider_name"], "registry.terraform.io/x/y"),
    "mixed_actions": _set(["resource_changes", "1", "change", "actions"], ["delete"]),
    "update_action": lambda d: [
        c["change"].update(actions=["update"]) for c in d["resource_changes"]
    ],
    "replace_action": lambda d: [
        c["change"].update(actions=["delete", "create"]) for c in d["resource_changes"]
    ],
    "no_op_action": lambda d: [
        c["change"].update(actions=["no-op"]) for c in d["resource_changes"]
    ],
    "read_action": lambda d: [c["change"].update(actions=["read"]) for c in d["resource_changes"]],
    "no_changes": _set(["resource_changes"], []),
    "pool_deletion_protected": _set(
        ["resource_changes", "0", "change", "after", "deletion_protection"], "ACTIVE"
    ),
    "pool_missing_tag": lambda d: _tags(d).pop("Ephemeral"),
    "pool_wrong_environment": lambda d: _tags(d).update(Environment="prod"),
    "pool_wrong_expiry_tag": lambda d: _tags(d).update(ExpiresOn="2099-01-01"),
    "pool_wrong_name": _set(["resource_changes", "0", "change", "after", "name"], "prod-users"),
    "client_has_secret": _set(
        ["resource_changes", "8", "change", "after", "generate_secret"], True
    ),
    "configured_unexpected_resource": lambda d: d["configuration"]["root_module"][
        "resources"
    ].append({"mode": "managed", "type": "aws_s3_bucket", "name": "x"}),
    "configured_data_source": lambda d: d["configuration"]["root_module"]["resources"].append(
        {"mode": "data", "type": "aws_caller_identity", "name": "x"}
    ),
    "module_calls": _set(
        ["configuration", "root_module", "module_calls"], {"x": {"source": "./x"}}
    ),
    "errored_plan": _set(["errored"], True),
    "not_applyable": _set(["applyable"], False),
    "incomplete_plan": _set(["complete"], False),
    "other_format_version": _set(["format_version"], "2.0"),
    "no_format_version": _drop(["format_version"]),
    "no_configuration": _drop(["configuration"]),
    "no_resource_changes": _drop(["resource_changes"]),
}


@pytest.mark.parametrize("case", sorted(JSON_CASES))
def test_apply_refuses_a_plan_whose_json_fails_verification_and_never_applies_it(
    root: Path, case: str
) -> None:
    name, sha = saved_plan(root)
    runner = FakeRunner(show_mutate=JSON_CASES[case])
    code, _, runner = run_cli(apply_args(name, sha, "--confirm-live"), root, runner=runner)
    assert code == 4
    assert runner.verbs == ["show"]  # inspected, and apply was never invoked


DELETE_JSON_CASES: dict[str, Any] = {
    "deletes_a_prod_pool": lambda d: d["resource_changes"][0]["change"]["before"][
        "tags_all"
    ].update(Environment="prod"),
    "deletes_an_untagged_pool": lambda d: d["resource_changes"][0]["change"]["before"][
        "tags_all"
    ].clear(),
    "deletes_extra_resources": _extra_change("aws_cognito_user_pool_client"),
    "deletes_an_unexpected_type": _extra_change("aws_iam_role"),
    "variable_other_account": _set(["variables", "expected_account_id", "value"], OTHER_ACCOUNT),
}


@pytest.mark.parametrize("case", sorted(DELETE_JSON_CASES))
def test_apply_refuses_an_unsafe_destroy_plan(root: Path, case: str) -> None:
    name, sha = saved_plan(root)
    runner = FakeRunner(show_kind="delete", show_mutate=DELETE_JSON_CASES[case])
    code, _, runner = run_cli(apply_args(name, sha, "--confirm-live"), root, runner=runner)
    assert code == 4 and runner.verbs == ["show"]


def test_a_partial_destroy_plan_is_accepted(root: Path) -> None:
    name, sha = saved_plan(root)
    runner = FakeRunner(show_kind="delete", show_mutate=_remove_change)  # fewer than nine left
    code, _, runner = run_cli(apply_args(name, sha, "--confirm-live"), root, runner=runner)
    assert code == 0 and runner.verbs == ["show", "apply"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"show_rc": 1},
        {"show_rc": 1, "show_stdout": json.dumps(plan_json())},  # failed, yet valid-looking JSON
        {"show_stdout": ""},
        {"show_stdout": "   \n"},
        {"show_stdout": "not json"},
        {"show_stdout": "{"},
        {"show_stdout": "[]"},
        {"show_stdout": "null"},
        {"show_stdout": '"a string"'},
        {"show_stdout": "123"},
        {"show_stdout": "{}"},
        {"show_stdout": '{"format_version": "1.2"}'},
        {"show_stdout": "[" * 200_000},  # deeply nested: must not crash the wrapper
    ],
    ids=[
        "terraform_failed",
        "failed_but_valid_json",
        "empty",
        "blank",
        "not_json",
        "truncated",
        "list",
        "null",
        "string",
        "number",
        "empty_object",
        "only_format_version",
        "recursion_bomb",
    ],
)
def test_unreadable_or_malformed_plan_json_is_refused(root: Path, kwargs: dict[str, Any]) -> None:
    name, sha = saved_plan(root)
    runner = FakeRunner(**kwargs)
    code, _, runner = run_cli(apply_args(name, sha, "--confirm-live"), root, runner=runner)
    assert code == 4 and runner.verbs == ["show"]


def test_oversized_plan_json_is_refused(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    name, sha = saved_plan(root)
    monkeypatch.setattr(tr, "MAX_SHOW_BYTES", 100)
    code, _, runner = run_cli(apply_args(name, sha, "--confirm-live"), root)
    assert code == 4 and runner.verbs == ["show"]


def test_verify_plan_document_returns_the_direction_and_enforces_the_expected_one() -> None:
    create, delete = plan_json(kind="create"), plan_json(kind="delete")
    assert tr.verify_plan_document(create, account_id=ACCOUNT, direction=None) == "create"
    assert tr.verify_plan_document(delete, account_id=ACCOUNT, direction=None) == "delete"
    assert tr.verify_plan_document(create, account_id=ACCOUNT, direction="create") == "create"
    for document, wrong in ((create, "delete"), (delete, "create")):
        with pytest.raises(tr.PlanVerificationError):
            tr.verify_plan_document(document, account_id=ACCOUNT, direction=wrong)
    with pytest.raises(tr.PlanVerificationError):
        tr.verify_plan_document(create, account_id=OTHER_ACCOUNT, direction=None)


# --- freshly created plans are verified too -------------------------------------------------------


@pytest.mark.parametrize(
    ("argv_head", "runner_kwargs"),
    [
        ("plan", {"show_kind": "delete"}),  # a "plan" that would destroy
        ("plan-destroy", {"show_kind": "create"}),  # a "destroy plan" that would create
        ("plan", {"show_account": OTHER_ACCOUNT}),
        ("plan-destroy", {"show_account": OTHER_ACCOUNT}),
        ("plan", {"show_mutate": _extra_change("aws_iam_role")}),
        ("plan", {"show_stdout": "garbage"}),
        ("plan", {"show_rc": 1}),
    ],
)
def test_a_new_plan_that_fails_verification_is_reported_and_not_endorsed(
    root: Path,
    argv_head: str,
    runner_kwargs: dict[str, Any],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = tmp_path / "record.json"
    argv = [argv_head, *plan_args("--confirm-live", "--record", str(record))[1:]]
    code, _, runner = run_cli(argv, root, runner=FakeRunner(**runner_kwargs))
    out = capsys.readouterr().out
    assert code == tr.EXIT_PLAN_UNVERIFIED == 5
    assert "do not apply" in out and "plan_sha256" not in out and "plan_verified" not in out
    data = json.loads(record.read_text())
    assert data["plan_verified"] is False and data["plan_sha256"] is None


# --- plan and destroy-plan receive equivalent identity checks -----------------------------------


def test_plan_and_destroy_plan_run_the_same_checks_in_the_same_order(root: Path) -> None:
    results = {}
    for operation in ("plan", "plan-destroy"):
        argv = [operation, *plan_args("--confirm-live", out=f"{operation}.tfplan")[1:]]
        code, factory, runner = run_cli(argv, root)
        results[operation] = (code, factory, runner)
    (c1, f1, r1), (c2, f2, r2) = results["plan"], results["plan-destroy"]
    assert c1 == c2 == 0
    assert r1.verbs == r2.verbs == ["plan", "show"]
    assert [c.secrets() for c in f1.created] == [c.secrets() for c in f2.created]
    assert f1.sts.calls == f2.sts.calls == 1

    # identical child environments (apart from per-run private file paths); only -destroy differs
    def stable(env: dict[str, str]) -> dict[str, str]:
        private = ("AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "TF_CLI_CONFIG_FILE")
        return {k: v for k, v in env.items() if k not in private}

    assert [stable(c["env"]) for c in r1.calls] == [stable(c["env"]) for c in r2.calls]
    assert r1.calls[0]["cwd"] == r2.calls[0]["cwd"] == root
    plan_cmd, destroy_cmd = r1.calls[0]["argv"], r2.calls[0]["argv"]
    assert [a for a in destroy_cmd if a != "-destroy"] == [
        a.replace("plan.tfplan", "plan-destroy.tfplan") for a in plan_cmd
    ]


@pytest.mark.parametrize("kind", sorted(BAD_CALLERS))
def test_every_bad_caller_gets_the_same_refusal_for_plan_and_destroy_plan(
    root: Path, kind: str, capsys: pytest.CaptureFixture[str]
) -> None:
    outputs = []
    for operation in ("plan", "plan-destroy"):
        argv = [operation, *plan_args("--confirm-live", out=f"{operation}.tfplan")[1:]]
        factory = StsFactory(FakeSts(**BAD_CALLERS[kind]))
        code, _, runner = run_cli(argv, root, factory=factory)
        outputs.append((code, runner.calls, capsys.readouterr().out))
    assert outputs[0] == outputs[1] == (4, [], outputs[0][2])


@pytest.mark.parametrize("operation", ["plan", "plan-destroy"])
def test_the_lifetime_and_expiration_rules_are_identical_for_plan_and_destroy_plan(
    root: Path, operation: str
) -> None:
    for expiration, accepted in (
        (None, False),
        ("2026-11-04T22:19:59+00:00", False),
        ("2026-11-04T22:20:00+00:00", True),
    ):
        argv = [operation, *plan_args("--confirm-live", out=f"{operation}-{accepted}.tfplan")[1:]]
        env = good_env(AWS_CREDENTIAL_EXPIRATION=expiration)
        code, _, _ = run_cli(argv, root, env=env)
        assert (code == 0) is accepted


# --- failures, logs and evidence ------------------------------------------------------------------


def test_terraform_failure_is_reported_without_a_plan_hash(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = FakeRunner(returncode=1, stderr="Error: something failed")
    code, _, _ = run_cli(plan_args("--confirm-live"), root, runner=runner)
    out = capsys.readouterr().out
    assert code == 1 and "plan_sha256" not in out and "terraform failed" in out
    assert not (root / "new.tfplan").exists()


def test_terraform_output_is_scrubbed_of_credentials(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    leaky = f"key={KEY} secret={SECRET} token={TOKEN} other={'AKIA' + 'Z' * 16}"
    runner = FakeRunner(stdout=leaky, stderr=leaky)
    code, _, _ = run_cli(plan_args("--confirm-live"), root, runner=runner)
    output = capsys.readouterr()
    text = output.out + output.err
    assert code == 0 and "[REDACTED]" in text
    assert not any(secret in text for secret in SECRETS) and "AKIA" not in text


def test_refusals_and_records_never_contain_credentials(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    record = tmp_path / "records" / "run.json"
    code, _, _ = run_cli(plan_args("--confirm-live", "--record", str(record)), root)
    assert code == 0
    body = record.read_text()
    data = json.loads(body)
    assert data["operation"] == "plan" and data["role"] == ROLE and data["account_verified"] is True
    assert data["terraform_exit_code"] == 0 and len(data["plan_sha256"]) == 64
    assert ACCOUNT not in body and "synthetic-session" not in body
    assert not any(secret in body for secret in SECRETS)
    for kind in ("iam_user", "wrong_account", "expired_token"):
        factory = StsFactory(FakeSts(**BAD_CALLERS[kind]))
        run_cli(plan_args("--confirm-live", out=f"{kind}.tfplan"), root, factory=factory)
    output = capsys.readouterr()
    assert not any(secret in output.out + output.err for secret in SECRETS)


def test_apply_record_pins_the_applied_plan_hash(root: Path, tmp_path: Path) -> None:
    name, sha = saved_plan(root)
    record = tmp_path / "apply.json"
    code, _, _ = run_cli(apply_args(name, sha, "--confirm-live", "--record", str(record)), root)
    assert code == 0 and json.loads(record.read_text())["plan_sha256"] == sha


def test_record_writer_refuses_credential_material(tmp_path: Path) -> None:
    with pytest.raises(tr.RefusedError):
        tr._write_record(tmp_path / "r.json", {"note": f"oops {SECRET}"}, SECRETS)
    with pytest.raises(tr.RefusedError):
        tr._write_record(tmp_path / "r.json", {"note": "AKIA" + "Z" * 16}, SECRETS)
    assert not (tmp_path / "r.json").exists()


def test_default_runner_never_reads_a_terminal_and_passes_a_fixed_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    class Done:
        returncode, stdout, stderr = 0, "out", "err"

    def fake_run(argv: list[str], **kwargs: Any) -> Done:
        captured.update(argv=argv, **kwargs)
        return Done()

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/terraform")
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = tr.subprocess_runner(["terraform", "plan"], tmp_path, {"A": "b"})
    assert result == tr.RunResult(0, "out", "err")
    assert captured["argv"] == ["/usr/bin/terraform", "plan"]
    assert captured["stdin"] is subprocess.DEVNULL and captured["env"] == {"A": "b"}
    assert "shell" not in captured or captured["shell"] is False


def test_missing_terraform_binary_is_a_refusal_not_a_crash(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    code = tr.main(
        plan_args("--confirm-live"),
        env=good_env(),
        sts_factory=StsFactory(),
        now=lambda: NOW,
        root=root,
    )
    assert code == 4 and "terraform executable not found" in capsys.readouterr().out


def test_script_entrypoint_dry_run_against_the_real_root(
    capsys: pytest.CaptureFixture[str],
) -> None:
    spec = importlib.util.spec_from_file_location(
        "identity_eval_terraform", REPO_ROOT / "scripts" / "identity_eval_terraform.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    code = module.main(plan_args(out="dry-run-only.tfplan"))
    assert code == 0 and "DRY RUN" in capsys.readouterr().out
    assert not (tr.EVAL_ROOT / "dry-run-only.tfplan").exists()
