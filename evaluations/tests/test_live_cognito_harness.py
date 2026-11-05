"""Offline checks of the M8.5 live Cognito harness (no AWS, no network).

A scripted fake cognito-idp client mints Cognito-shaped access and ID tokens
with synthetic RSA keys generated at test time, and a fake HTTPS layer serves
discovery and JWKS. The verifier under test is the production one built from
settings. These tests prove the harness logic, guards, cleanup and evidence
hygiene; they make no claim about real Cognito behavior.
"""

import email.message
import importlib.util
import io
import json
import re
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import jwt
import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import rsa

from evaluations.live import m8_5_cognito as harness

REPO_ROOT = Path(__file__).resolve().parents[2]
REGION = "us-east-1"
POOL_ID = "us-east-1_FakeM85Pool"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL_ID}"
APP_CLIENT = "fakeappclient01"
OTHER_CLIENT = "fakeotherclient02"
EXPIRY_LIFETIME = 2
ACCOUNT_ID = "111122223333"  # synthetic; never a real account
ROLE = harness.DEFAULT_HARNESS_ROLE


def client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "synthetic"}}, "Fake")


class FakeSts:
    """sts double: by default an assumed-role session in the expected account."""

    def __init__(
        self, arn: str | None = None, account: str = ACCOUNT_ID, error: Any = None
    ) -> None:
        self.arn = arn or f"arn:aws:sts::{account}:assumed-role/{ROLE}/synthetic-session"
        self.account = account
        self.error = error
        self.calls = 0

    def get_caller_identity(self) -> dict[str, Any]:
        self.calls += 1
        if self.error is not None:
            raise self.error
        identity = {"UserId": "AROASYNTHETIC:synthetic-session", "Account": self.account}
        return {**identity, "Arn": self.arn}


class FakeCognito:
    """Minimal cognito-idp double with Cognito-shaped tokens."""

    def __init__(self) -> None:
        self.keys = {
            "fake-access-kid": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "fake-id-kid": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        }
        self.pool: dict[str, Any] = {
            "Name": "rag-identity-eval-m85-pool",
            "Arn": f"arn:aws:cognito-idp:{REGION}:{ACCOUNT_ID}:userpool/{POOL_ID}",
            "DeletionProtection": "INACTIVE",
            "UserPoolTags": dict(harness.REQUIRED_POOL_TAGS),
        }
        self.clients: dict[str, dict[str, Any]] = {
            c: {"ClientId": c, "ExplicitAuthFlows": ["ALLOW_ADMIN_USER_PASSWORD_AUTH"]}
            for c in (APP_CLIENT, OTHER_CLIENT)
        }
        self.users: dict[str, dict[str, Any]] = {}
        self.created: list[str] = []
        self.passwords: list[str] = []
        self.minted: list[str] = []
        self.refresh_tokens: dict[str, str] = {}
        self.fail_delete: set[str] = set()
        self.hooks: dict[str, Any] = {}
        self.api_calls: list[str] = []

    def _hook(self, name: str, **kwargs: Any) -> None:
        self.api_calls.append(name)
        if name in self.hooks:
            self.hooks[name](**kwargs)

    def jwks(self) -> dict[str, Any]:
        keys = []
        for kid, key in self.keys.items():
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
            jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
            keys.append(jwk)
        return {"keys": keys}

    # -- API surface used by CognitoAdmin --

    def describe_user_pool(self, UserPoolId: str) -> dict[str, Any]:
        self._hook("describe_user_pool")
        return {"UserPool": self.pool}

    def describe_user_pool_client(self, UserPoolId: str, ClientId: str) -> dict[str, Any]:
        self._hook("describe_user_pool_client")
        return {"UserPoolClient": self.clients[ClientId]}

    def admin_create_user(self, UserPoolId: str, Username: str, MessageAction: str) -> None:
        self._hook("admin_create_user", Username=Username)
        assert MessageAction == "SUPPRESS"
        if Username in self.users:
            raise client_error("UsernameExistsException")
        self.users[Username] = {"groups": [], "sub": str(uuid.uuid4()), "password": None}
        self.created.append(Username)

    def admin_set_user_password(
        self, UserPoolId: str, Username: str, Password: str, Permanent: bool
    ) -> None:
        self._hook("admin_set_user_password")
        assert Permanent is True
        self.users[Username]["password"] = Password
        self.passwords.append(Password)

    def admin_add_user_to_group(self, UserPoolId: str, Username: str, GroupName: str) -> None:
        self._hook("admin_add_user_to_group", Username=Username)
        self.users[Username]["groups"].append(GroupName)

    def admin_remove_user_from_group(self, UserPoolId: str, Username: str, GroupName: str) -> None:
        self._hook("admin_remove_user_from_group")
        self.users[Username]["groups"].remove(GroupName)

    def _mint(self, username: str, client_id: str) -> dict[str, str]:
        user = self.users[username]
        now = int(time.time())
        lifetime = EXPIRY_LIFETIME if username.endswith("-expiry") else 300
        common = {"sub": user["sub"], "iss": ISSUER, "auth_time": now, "iat": now}
        if user["groups"]:
            common["cognito:groups"] = list(user["groups"])
        access = {
            **common,
            "version": 2,
            "client_id": client_id,
            "origin_jti": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "token_use": "access",
            "scope": "aws.cognito.signin.user.admin",
            "exp": now + lifetime,
            "jti": str(uuid.uuid4()),
            "username": username,
        }
        ident = {
            **common,
            "aud": client_id,
            "cognito:username": username,
            "token_use": "id",
            "exp": now + lifetime,
            "jti": str(uuid.uuid4()),
        }
        tokens = {
            "AccessToken": jwt.encode(
                access, self.keys["fake-access-kid"], "RS256", {"kid": "fake-access-kid"}
            ),
            "IdToken": jwt.encode(ident, self.keys["fake-id-kid"], "RS256", {"kid": "fake-id-kid"}),
            "RefreshToken": "fake-refresh-" + uuid.uuid4().hex + uuid.uuid4().hex,
        }
        self.refresh_tokens[tokens["RefreshToken"]] = username
        self.minted.extend(tokens.values())
        return tokens

    def admin_initiate_auth(
        self, UserPoolId: str, ClientId: str, AuthFlow: str, AuthParameters: dict[str, str]
    ) -> dict[str, Any]:
        self._hook("admin_initiate_auth")
        assert ClientId in self.clients
        if AuthFlow == "ADMIN_USER_PASSWORD_AUTH":
            user = self.users.get(AuthParameters["USERNAME"])
            if user is None or user["password"] != AuthParameters["PASSWORD"]:
                raise client_error("NotAuthorizedException")
            return {"AuthenticationResult": self._mint(AuthParameters["USERNAME"], ClientId)}
        assert AuthFlow == "REFRESH_TOKEN_AUTH"
        username = self.refresh_tokens.get(AuthParameters["REFRESH_TOKEN"])
        if username is None:
            raise client_error("NotAuthorizedException")
        access = self._mint(username, ClientId)["AccessToken"]
        return {"AuthenticationResult": {"AccessToken": access}}

    def admin_user_global_sign_out(self, UserPoolId: str, Username: str) -> None:
        self._hook("admin_user_global_sign_out")
        for token, owner in list(self.refresh_tokens.items()):
            if owner == Username:
                del self.refresh_tokens[token]

    def admin_delete_user(self, UserPoolId: str, Username: str) -> None:
        self._hook("admin_delete_user")
        if Username in self.fail_delete:
            raise client_error("InternalErrorException")
        if self.users.pop(Username, None) is None:
            raise client_error("UserNotFoundException")

    def admin_get_user(self, UserPoolId: str, Username: str) -> dict[str, Any]:
        self._hook("admin_get_user")
        if Username not in self.users:
            raise client_error("UserNotFoundException")
        return {"Username": Username}

    def list_users(self, UserPoolId: str, Filter: str, Limit: int, **kwargs: Any) -> dict[str, Any]:
        self._hook("list_users")
        match = re.fullmatch(r'username \^= "(.*)"', Filter)
        assert match is not None
        names = sorted(u for u in self.users if u.startswith(match.group(1)))
        start = int(kwargs.get("PaginationToken", 0))
        page = names[start : start + 3]  # small pages exercise pagination
        response: dict[str, Any] = {"Users": [{"Username": n} for n in page]}
        if start + 3 < len(names):
            response["PaginationToken"] = str(start + 3)
        return response


class _Response(io.BytesIO):
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: Any) -> None:
        return None


class FakeHttps:
    """Discovery and JWKS for the fake issuer; every other URL is an HTTP 400."""

    def __init__(self, cognito: FakeCognito) -> None:
        self.cognito = cognito
        self.jwks_available = True
        self.requests: list[str] = []

    def build_opener(self, *handlers: Any) -> Any:
        fake = self

        class _Opener:
            def open(self, request: Any, timeout: float | None = None) -> _Response:
                url = request.full_url if isinstance(request, urllib.request.Request) else request
                fake.requests.append(url)
                if url == f"{ISSUER}/.well-known/openid-configuration":
                    body: Any = {
                        "issuer": ISSUER,
                        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
                        "id_token_signing_alg_values_supported": ["RS256"],
                    }
                elif url == f"{ISSUER}/.well-known/jwks.json" and fake.jwks_available:
                    body = fake.cognito.jwks()
                else:
                    raise urllib.error.HTTPError(
                        url, 400, "Bad Request", email.message.Message(), io.BytesIO(b"{}")
                    )
                return _Response(json.dumps(body).encode())

        return _Opener()


@pytest.fixture()
def cognito() -> FakeCognito:
    return FakeCognito()


@pytest.fixture()
def https(cognito: FakeCognito, monkeypatch: pytest.MonkeyPatch) -> FakeHttps:
    fake = FakeHttps(cognito)
    monkeypatch.setattr(urllib.request, "build_opener", fake.build_opener)
    return fake


def jwt_shaped(subject: str) -> str:
    """A JWT-shaped string built at runtime (no token literal in source)."""
    header = harness._b64({"alg": "RS256", "kid": "k"})
    return f"{header}.{harness._b64({'sub': subject})}.c2lnbmF0dXJlLXBhcnQ"


def config(**overrides: Any) -> harness.HarnessConfig:
    values: dict[str, Any] = {
        "region": REGION,
        "user_pool_id": POOL_ID,
        "app_client_id": APP_CLIENT,
        "other_client_id": OTHER_CLIENT,
        "run_id": "testrun01",
        "expected_account_id": ACCOUNT_ID,
        "leeway_seconds": 0,
    }
    values.update(overrides)
    return harness.HarnessConfig(**values)


def run(
    tmp_path: Path, cognito: FakeCognito, **overrides: Any
) -> tuple[int, dict[str, Any], Path, Path]:
    evidence = tmp_path / "evidence.json"
    manifest = tmp_path / "manifest" / "testrun01.json"
    code, document = harness.run(
        config(**overrides),
        cognito,
        sts_client=FakeSts(),
        evidence_path=evidence,
        manifest_path=manifest,
    )
    return code, document, evidence, manifest


def statuses(document: dict[str, Any]) -> dict[str, str]:
    return {c["id"]: c["status"] for c in document["cases"]}


def observed(document: dict[str, Any], case_id: str) -> dict[str, Any]:
    return next(c["observed"] for c in document["cases"] if c["id"] == case_id)


# --- the full matrix ----------------------------------------------------------------


def test_full_matrix_passes_and_cleans_up(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    code, document, evidence, manifest = run(tmp_path, cognito)
    assert statuses(document) == {
        "R-01": "PASS",
        "R-02": "PASS",
        "R-03": "PASS",
        "R-04": "PASS",
        "R-05": "PASS",
        "R-06": "PASS",
        "R-07": "PASS",
        "R-08": "PASS",
        "R-09": "PASS",
        "R-10": "PASS",
        "R-11": "PASS",
        "R-12": "PASS",
        "R-13": "PASS",
        "R-14": "NOT_TESTABLE",
        "R-15": "SKIPPED",
        "R-16": "LIMITATION_CONFIRMED",
        "R-17": "LIMITATION_CONFIRMED",
        "R-18": "PASS",
    }
    assert (code, document["overall"]) == (0, "PASS")
    assert document["cleanup"]["verified"] is True
    assert len(document["cleanup"]["deleted"]) == len(harness.USERS)
    assert cognito.users == {}
    assert not manifest.exists()
    assert json.loads(evidence.read_text())["overall"] == "PASS"
    r03 = observed(document, "R-03")
    assert r03["token_use"] == "access" and r03["aud_present"] is False  # noqa: S105
    assert {"sub", "client_id", "cognito:groups", "token_use"} <= set(r03["claim_names"])
    assert observed(document, "R-05")["reason"] == "missing_claim"
    assert observed(document, "R-11")["jwks_fetches"] == 1
    assert observed(document, "R-12")["jwks_fetches"] <= 2


def test_wrong_issuer_is_distinguished_from_jwks_unavailability(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    _, document, _, _ = run(tmp_path, cognito, skip_expiry=True)
    r09, r13 = observed(document, "R-09"), observed(document, "R-13")
    assert r09["reason"] == "wrong_issuer"
    assert r09["jwks_available"] is True and r09["real_jwks_fetches"] >= 1
    assert r13["reasons"] == ["unavailable:jwks_unavailable"]
    assert r13["jwks_fetches"] == 1 and r13["http_status"] == 503


def test_unreachable_real_jwks_fails_r09_instead_of_passing_it(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    https.jwks_available = False
    code, document, _, _ = run(tmp_path, cognito, skip_expiry=True)
    assert statuses(document)["R-09"] == "FAIL"
    assert observed(document, "R-09")["reason"] == "unavailable:jwks_unavailable"
    assert observed(document, "R-09")["jwks_available"] is False
    assert (code, document["overall"]) == (1, "FAIL")
    assert document["cleanup"]["verified"] is True and cognito.users == {}


def test_skipped_expiry_is_reported_incomplete_not_pass(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    code, document, _, _ = run(tmp_path, cognito, skip_expiry=True)
    assert statuses(document)["R-10"] == "SKIPPED"
    assert (code, document["overall"]) == (3, "INCOMPLETE")


def test_lifetime_mismatch_fails_r03(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    _, document, _, _ = run(tmp_path, cognito, skip_expiry=True, expected_access_token_lifetime=600)
    assert statuses(document)["R-03"] == "FAIL"


# --- secrets never leave memory ------------------------------------------------------


def test_evidence_and_output_contain_no_tokens_passwords_or_subjects(
    tmp_path: Path,
    cognito: FakeCognito,
    https: FakeHttps,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    _, document, evidence, _ = run(tmp_path, cognito, skip_expiry=True)
    texts = [evidence.read_text(), json.dumps(document), caplog.text, "".join(capsys.readouterr())]
    secrets = [*cognito.passwords, *(u["sub"] for u in cognito.users.values())]
    secrets += [s for t in cognito.minted for s in [t, *t.split(".")] if len(s) >= 16]
    assert len(cognito.passwords) == len(harness.USERS) and cognito.minted
    for text in texts:
        for value in secrets:
            assert value not in text
        assert not harness.JWT_SHAPE.search(text)
        assert "Bearer " not in text
    assert observed(document, "R-18")["detector_self_test"] is True


def test_subject_identifiers_are_registered_and_never_recorded(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    subs: list[str] = []
    original = cognito.admin_delete_user

    def capture_sub(UserPoolId: str, Username: str) -> None:
        if Username in cognito.users:
            subs.append(cognito.users[Username]["sub"])
        original(UserPoolId, Username)

    cognito.admin_delete_user = capture_sub  # type: ignore[method-assign]
    _, _, evidence, _ = run(tmp_path, cognito, skip_expiry=True)
    text = evidence.read_text()
    assert len(subs) == len(harness.USERS)
    assert not any(sub in text for sub in subs)


def test_write_evidence_refuses_secret_material(tmp_path: Path) -> None:
    registry = harness.SecretRegistry()
    registry.add("synthetic-password-value-123")
    target = tmp_path / "evidence.json"
    leaked = [
        {"x": "synthetic-password-value-123"},
        {"x": jwt_shaped("x")},
        {"x": "Bearer abc"},
    ]
    for document in leaked:
        with pytest.raises(harness.EvidenceLeakError) as excinfo:
            harness.write_evidence(target, document, registry)
        assert "synthetic-password-value-123" not in str(excinfo.value)
        assert not target.exists()
    harness.write_evidence(target, {"x": "clean"}, registry)
    assert target.exists()


def test_r18_detects_a_logged_token_and_requires_a_working_detector() -> None:
    registry = harness.SecretRegistry()
    token = jwt_shaped("synthetic")
    registry.add(token)
    assert harness.r18_log_hygiene("clean output", registry).status == "PASS"
    assert harness.r18_log_hygiene(f"oops {token.split('.')[2]}", registry).status == "FAIL"
    assert harness.r18_log_hygiene("Authorization: Bearer x", registry).status == "FAIL"
    assert harness.r18_log_hygiene("clean", harness.SecretRegistry()).status == "FAIL"


def test_passwords_meet_the_pool_policy_and_are_unique() -> None:
    values = {harness.new_password() for _ in range(50)}
    assert len(values) == 50
    for value in values:
        assert len(value) >= 24
        assert re.search(r"[a-z]", value) and re.search(r"[A-Z]", value)
        assert re.search(r"\d", value) and re.search(r"[^A-Za-z0-9]", value)


# --- guards and configuration ----------------------------------------------------------


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.pool.update(Name="production-users"),
        lambda c: c.pool["UserPoolTags"].pop("Ephemeral"),
        lambda c: c.pool["UserPoolTags"].update(Environment="prod"),
        lambda c: c.pool.update(DeletionProtection="ACTIVE"),
        lambda c: c.pool.update(Arn=f"arn:aws:cognito-idp:{REGION}:999988887777:userpool/x"),
        lambda c: c.clients[APP_CLIENT].update(ClientSecret="synthetic-secret-value"),
        lambda c: c.clients[OTHER_CLIENT].update(ExplicitAuthFlows=["ALLOW_USER_SRP_AUTH"]),
    ],
    ids=[
        "name",
        "ephemeral_tag",
        "environment_tag",
        "deletion_protection",
        "pool_arn_account",
        "secret",
        "flows",
    ],
)
def test_guard_refuses_anything_but_the_evaluation_pool(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps, mutate: Any
) -> None:
    mutate(cognito)
    code, document, _, manifest = run(tmp_path, cognito)
    assert (code, document["overall"]) == (4, "GUARD_FAILED")
    assert cognito.created == []
    assert not any(c.startswith("admin_") or c == "list_users" for c in cognito.api_calls)
    assert document["cases"] == [] and not manifest.exists()


@pytest.mark.parametrize(
    "overrides",
    [
        {"user_pool_id": "us-west-2_FakeM85Pool"},
        {"user_pool_id": "not-a-pool"},
        {"other_client_id": APP_CLIENT},
        {"app_client_id": "bad id!"},
        {"run_id": "UPPER"},
        {"region": "nowhere"},
        {"expected_account_id": ""},
        {"expected_account_id": "12345678901"},
        {"expected_account_id": "1234567890123"},
        {"expected_account_id": "11112222333a"},
        {"expected_role_name": "bad/role"},
    ],
)
def test_configuration_is_validated_before_any_call(overrides: dict[str, Any]) -> None:
    with pytest.raises(harness.HarnessError):
        config(**overrides)


# --- account guard: fail closed before any Cognito call ---------------------------------------


def _sts_arn(kind: str, account: str = ACCOUNT_ID) -> str:
    return f"arn:aws:sts::{account}:{kind}"


@pytest.mark.parametrize(
    "sts_kwargs",
    [
        {"account": "999988887777"},  # right shape, wrong account
        {"arn": f"arn:aws:iam::{ACCOUNT_ID}:user/terraform-user"},  # long-lived IAM user
        {"arn": f"arn:aws:iam::{ACCOUNT_ID}:root"},
        {"arn": _sts_arn("federated-user/someone")},
        {"arn": _sts_arn("assumed-role/some-other-role/synthetic-session")},
        {"arn": _sts_arn(f"assumed-role/{ROLE}/synthetic-session", "999988887777")},
        {"arn": f"arn:aws-cn:sts::{ACCOUNT_ID}:assumed-role/{ROLE}/synthetic-session"},
        {"arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{ROLE}/synthetic-session/extra"},
        {"arn": f" arn:aws:sts::{ACCOUNT_ID}:assumed-role/{ROLE}/synthetic-session"},
        {"arn": None, "error": client_error("ExpiredToken")},
        {"arn": None, "error": RuntimeError("no credentials")},
    ],
    ids=[
        "account_field",
        "iam_user",
        "root",
        "federated",
        "other_role",
        "arn_account",
        "other_partition",
        "extra_segment",
        "leading_space",
        "sts_client_error",
        "sts_unreachable",
    ],
)
def test_account_guard_refuses_before_any_cognito_call(
    tmp_path: Path, cognito: FakeCognito, sts_kwargs: dict[str, Any]
) -> None:
    sts = FakeSts(**sts_kwargs)
    with pytest.raises(harness.GuardError) as caught:
        harness.run(
            config(),
            cognito,
            sts_client=sts,
            evidence_path=tmp_path / "evidence.json",
            manifest_path=tmp_path / "m.json",
        )
    assert sts.calls == 1
    assert cognito.api_calls == [] and cognito.created == []
    assert not (tmp_path / "evidence.json").exists() and not (tmp_path / "m.json").exists()
    message = str(caught.value)
    assert ACCOUNT_ID not in message and "999988887777" not in message
    assert "synthetic-session" not in message


def test_account_guard_also_protects_cleanup_only(tmp_path: Path, cognito: FakeCognito) -> None:
    cognito.users["m85-eval-oldrun01-reader-a"] = {"groups": [], "sub": "x", "password": None}
    with pytest.raises(harness.GuardError):
        harness.cleanup_only(
            config(),
            cognito,
            sts_client=FakeSts(account="999988887777"),
            manifest_path=tmp_path / "m.json",
            all_runs=True,
        )
    assert cognito.api_calls == [] and "m85-eval-oldrun01-reader-a" in cognito.users


def test_missing_sts_client_fails_closed(tmp_path: Path, cognito: FakeCognito) -> None:
    with pytest.raises(harness.GuardError):
        harness.run(
            config(),
            cognito,
            sts_client=None,
            evidence_path=tmp_path / "e.json",
            manifest_path=tmp_path / "m.json",
        )
    assert cognito.api_calls == []


def test_account_guard_runs_once_and_is_recorded_without_session_details(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    code, document, evidence, _ = run(tmp_path, cognito, skip_expiry=True)
    assert document["account_guard"] == {
        "account_verified": True,
        "credential_type": "assumed-role",
        "role": ROLE,
    }
    assert "synthetic-session" not in evidence.read_text()


def test_expected_role_name_is_configurable() -> None:
    sts = FakeSts(arn=f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/AWSReservedSSO_eval/me@example.com")
    result = harness.verify_caller_account(sts, config(expected_role_name="AWSReservedSSO_eval"))
    assert result["role"] == "AWSReservedSSO_eval"


# --- interruption, failure and recovery -------------------------------------------------


def test_interrupt_mid_run_still_deletes_every_user(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    def interrupt(**_: Any) -> None:
        raise KeyboardInterrupt

    cognito.hooks["admin_user_global_sign_out"] = interrupt
    code, document, _, manifest = run(tmp_path, cognito)
    assert (code, document["overall"]) == (3, "INTERRUPTED")
    assert document["cleanup"]["verified"] is True
    assert cognito.users == {} and not manifest.exists()


def test_failure_during_provisioning_cleans_up_partial_users(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    def fail_third(**kwargs: Any) -> None:
        if len(cognito.created) == 3:
            raise client_error("TooManyRequestsException")

    cognito.hooks["admin_add_user_to_group"] = fail_third
    code, document, _, _ = run(tmp_path, cognito)
    assert (code, document["overall"], document["error"]) == (
        3,
        "ERROR",
        "TooManyRequestsException",
    )
    assert cognito.users == {} and document["cleanup"]["verified"] is True


def test_manifest_records_each_user_before_it_is_created(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    manifest = tmp_path / "manifest" / "testrun01.json"
    seen: list[bool] = []

    def check(Username: str) -> None:
        seen.append(Username in json.loads(manifest.read_text())["users"])

    cognito.hooks["admin_create_user"] = check
    run(tmp_path, cognito, skip_expiry=True)
    assert seen == [True] * len(harness.USERS)


def test_unverified_cleanup_is_never_pass_and_is_recoverable(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    stuck = config().username("reader-a")
    cognito.fail_delete = {stuck}
    code, document, _, manifest = run(tmp_path, cognito, skip_expiry=True)
    assert (code, document["overall"]) == (2, "INCOMPLETE_CLEANUP")
    cleanup = document["cleanup"]
    assert cleanup["verified"] is False
    assert cleanup["errors"] == [{"user": stuck, "error": "InternalErrorException"}]
    assert cleanup["remaining_listed"] == [stuck] == cleanup["remaining_get_user"]
    kept = json.loads(manifest.read_text())
    assert kept["status"] == "cleanup_unverified" and stuck in kept["users"]
    assert "password" not in manifest.read_text().lower()

    cognito.fail_delete = set()
    code, report = harness.cleanup_only(
        config(), cognito, sts_client=FakeSts(), manifest_path=manifest, all_runs=False
    )
    assert (code, report["verified"], report["deleted"]) == (0, True, [stuck])
    assert cognito.users == {} and not manifest.exists()


def test_cleanup_verification_failure_is_reported_not_assumed(
    tmp_path: Path, cognito: FakeCognito, https: FakeHttps
) -> None:
    def broken(**_: Any) -> None:
        if cognito.api_calls.count("admin_get_user") > 3:
            raise client_error("AccessDeniedException")

    cognito.hooks["admin_get_user"] = broken
    code, document, _, _ = run(tmp_path, cognito, skip_expiry=True)
    assert (code, document["overall"]) == (2, "INCOMPLETE_CLEANUP")
    errors = document["cleanup"]["verification_errors"]
    assert errors and all(e["error"] == "AccessDeniedException" for e in errors)


def test_cleanup_only_all_runs_removes_only_harness_users(
    tmp_path: Path, cognito: FakeCognito
) -> None:
    leftovers = ["m85-eval-oldrun01-reader-a", "m85-eval-oldrun02-admin-a"]
    for name in [*leftovers, "real-person", "m85-other"]:
        cognito.users[name] = {"groups": [], "sub": str(uuid.uuid4()), "password": None}
    code, report = harness.cleanup_only(
        config(run_id="recovery"),
        cognito,
        sts_client=FakeSts(),
        manifest_path=tmp_path / "recovery.json",
        all_runs=True,
    )
    assert (code, report["verified"]) == (0, True)
    assert sorted(report["deleted"]) == leftovers
    assert sorted(cognito.users) == ["m85-other", "real-person"]


def test_cleanup_only_refuses_a_non_evaluation_pool(tmp_path: Path, cognito: FakeCognito) -> None:
    cognito.pool["Name"] = "production-users"
    with pytest.raises(harness.GuardError):
        harness.cleanup_only(
            config(),
            cognito,
            sts_client=FakeSts(),
            manifest_path=tmp_path / "m.json",
            all_runs=True,
        )
    assert "admin_delete_user" not in cognito.api_calls


# --- CLI -----------------------------------------------------------------------------------


def load_cli() -> Any:
    spec = importlib.util.spec_from_file_location(
        "validate_live_cognito", REPO_ROOT / "scripts" / "validate_live_cognito.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CLI_ARGS = [
    "--expected-account-id",
    ACCOUNT_ID,
    "--user-pool-id",
    POOL_ID,
    "--app-client-id",
    APP_CLIENT,
    "--other-client-id",
    OTHER_CLIENT,
]


def test_cli_without_confirm_live_makes_no_aws_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import boto3

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("boto3 client created without --confirm-live")

    monkeypatch.setattr(boto3, "client", forbidden)
    cli = load_cli()
    assert cli.main([*CLI_ARGS, "--manifest-dir", str(tmp_path)]) == 0
    assert "no AWS call made" in capsys.readouterr().out
    assert cli.main([*CLI_ARGS, "--cleanup-only"]) == 4
    assert cli.main([*CLI_ARGS, "--user-pool-id", "us-west-2_X", "--confirm-live"]) == 4
    # the account id is mandatory even for the plan-only path
    without_account = CLI_ARGS[2:]
    assert cli.main([*without_account, "--manifest-dir", str(tmp_path)]) == 4
    assert cli.main([*without_account, "--confirm-live"]) == 4


def test_cli_refuses_wrong_account_and_missing_sts_double(
    tmp_path: Path, cognito: FakeCognito, capsys: pytest.CaptureFixture[str]
) -> None:
    cli = load_cli()
    live = [*CLI_ARGS, "--confirm-live", "--manifest-dir", str(tmp_path)]
    wrong = cli.main(
        live, client_factory=lambda: cognito, sts_factory=lambda: FakeSts(account="999988887777")
    )
    assert wrong == 4 and "refused: account guard" in capsys.readouterr().out
    assert cli.main([*live, "--cleanup-only", "--all-runs"], client_factory=lambda: cognito) == 4
    assert cognito.api_calls == []


def test_cli_live_run_against_fake_client(
    tmp_path: Path,
    cognito: FakeCognito,
    https: FakeHttps,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = load_cli()
    evidence = tmp_path / "evidence.json"
    code = cli.main(
        [
            *CLI_ARGS,
            "--confirm-live",
            "--skip-expiry",
            "--run-id",
            "clirun01",
            "--evidence",
            str(evidence),
            "--manifest-dir",
            str(tmp_path),
        ],
        client_factory=lambda: cognito,
        sts_factory=FakeSts,
    )
    out = capsys.readouterr().out
    assert code == 3  # INCOMPLETE: R-10 skipped is never reported as PASS
    assert "overall=INCOMPLETE" in out and "cleanup verified: True" in out
    assert cognito.users == {} and evidence.exists()


# --- Terraform root stays isolated and consistent with the harness ---------------------


def test_identity_eval_root_is_isolated_and_matches_harness_groups() -> None:
    root = REPO_ROOT / "infrastructure" / "environments" / "identity-eval"
    text = "\n".join(p.read_text() for p in sorted(root.glob("*.tf")))
    resource_types = set(re.findall(r'^resource "([a-z0-9_]+)"', text, re.MULTILINE))
    assert resource_types == {
        "aws_cognito_user_pool",
        "aws_cognito_user_group",
        "aws_cognito_user_pool_client",
    }
    assert 'backend "local"' in text and 'backend "s3"' not in text
    assert "allowed_account_ids" in text
    assert not re.search(r'^data "', text, re.MULTILINE)
    assert "generate_secret                      = false" in text
    assert 'deletion_protection = "INACTIVE"' in text
    groups = set(re.findall(r'"((?:tenant|role):[a-z-]+)"', text))
    harness_groups = {g for groups_ in harness.USERS.values() for g in groups_}
    assert harness_groups <= groups
    tags = dict(re.findall(r'^\s+(Environment|Ephemeral|Milestone)\s+= "([^"]+)"', text, re.M))
    assert tags == harness.REQUIRED_POOL_TAGS
    assert 'name                = "${local.name}-pool"' in text
    assert f'name = "{harness.POOL_NAME_PREFIX}"' in text
