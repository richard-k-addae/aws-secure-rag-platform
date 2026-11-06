"""M8.5 live Cognito validation harness (R-01 .. R-18).

Validates the PRODUCTION verifier (``app.auth.oidc.build_oidc_verifier``) and
identity mapping against real Cognito-issued tokens from the temporary
``identity-eval`` user pool. Run only through scripts/validate_live_cognito.py
and only after separate AWS authorization; never part of CI.

Secret handling (enforced, not just intended):

* Synthetic user passwords are generated in-process (``secrets``), never
  printed, logged, written to disk or passed on a command line.
* Tokens live in memory only. Every password, token, token segment and
  verified ``sub`` is registered in a ``SecretRegistry``; captured logs are
  scanned (R-18) and the evidence document is refused if it contains any
  registered value or anything shaped like a JWT.
* Evidence records claim NAMES, bounded reason codes, status codes, counts and
  synthetic group values - never token material or subject identifiers.

Cleanup: every username is written to a manifest BEFORE it is created; cleanup
deletes manifest users plus any user listed under the run prefix, then verifies
absence independently (ListUsers and AdminGetUser per user). If that cannot be
proven the run reports INCOMPLETE_CLEANUP and never PASS.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import re
import secrets
import string
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth import oidc
from app.auth.oidc import (
    AuthenticationError,
    AuthenticationUnavailableError,
    OidcConfig,
    OidcVerifier,
    TrustedJwksClient,
    VerifiedPrincipal,
)
from app.auth.tenancy import IdentityMappingError, TenantContext, map_principal
from app.core.config import Settings
from evaluations.live.aws_identity import (
    ACCOUNT_ID_PATTERN,
    IdentityGuardError,
    verify_assumed_role,
)

POOL_NAME_PREFIX = "rag-identity-eval-m85"
REQUIRED_POOL_TAGS = {"Environment": "identity-eval", "Ephemeral": "true", "Milestone": "M8.5"}
USER_PREFIX = "m85-eval-"
DEFAULT_HARNESS_ROLE = "rag-eval-harness"
TENANT_ALLOWLIST = "tenant-a,tenant-b"
HTTP_TIMEOUT_SECONDS = 5.0
MAX_EXPIRY_WAIT_SECONDS = 900
OPTIONAL_CASES = frozenset({"R-15"})

# key -> Cognito groups. One user per behavior so no case mutates another's input.
USERS: dict[str, tuple[str, ...]] = {
    "reader-a": ("tenant:tenant-a", "role:reader"),
    "admin-a": ("tenant:tenant-a", "role:admin"),
    "ingestor-b": ("tenant:tenant-b", "role:ingestor"),
    "nogroups": (),
    "two-tenants": ("tenant:tenant-a", "tenant:tenant-b", "role:reader"),
    "tenant-only": ("tenant:tenant-a",),
    "unknown-tenant": ("tenant:tenant-z", "role:reader"),
    "group-change": ("tenant:tenant-a", "role:reader"),
    "sign-out": ("tenant:tenant-a", "role:reader"),
    "expiry": ("tenant:tenant-a", "role:reader"),
}

PASS, FAIL, ERROR = "PASS", "FAIL", "ERROR"
SKIPPED, NOT_TESTABLE, LIMITATION = "SKIPPED", "NOT_TESTABLE", "LIMITATION_CONFIRMED"
GENERIC_BODIES = {
    401: {"detail": "Not authenticated"},
    403: {"detail": "Forbidden"},
    503: {"detail": "Authentication unavailable"},
}
JWT_SHAPE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


class HarnessError(Exception):
    """Configuration or precondition failure; carries no secret material."""


class GuardError(HarnessError):
    """The target is not the evaluation pool; nothing was created."""


class EvidenceLeakError(HarnessError):
    """The evidence document contained secret material and was not written."""


# --- configuration -------------------------------------------------------------------


@dataclass(frozen=True)
class HarnessConfig:
    region: str
    user_pool_id: str
    app_client_id: str
    other_client_id: str
    run_id: str
    expected_account_id: str
    expected_role_name: str = DEFAULT_HARNESS_ROLE
    leeway_seconds: int = 30
    jwks_cache_ttl_seconds: int = 300
    jwks_refresh_cooldown_seconds: int = 30
    expected_access_token_lifetime: int = 300
    skip_expiry: bool = False

    def __post_init__(self) -> None:
        if not re.fullmatch(ACCOUNT_ID_PATTERN, self.expected_account_id):
            raise HarnessError("expected account id must be a 12-digit AWS account id")
        if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", self.expected_role_name):
            raise HarnessError("invalid expected role name")
        if not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", self.region):
            raise HarnessError("invalid region")
        if not re.fullmatch(rf"{re.escape(self.region)}_[A-Za-z0-9]{{1,55}}", self.user_pool_id):
            raise HarnessError("user pool id does not belong to the configured region")
        for client_id in (self.app_client_id, self.other_client_id):
            if not re.fullmatch(r"[A-Za-z0-9]{1,128}", client_id):
                raise HarnessError("invalid app client id")
        if self.app_client_id == self.other_client_id:
            raise HarnessError("the wrong-client case needs two distinct clients")
        if not re.fullmatch(r"[a-z0-9]{6,16}", self.run_id):
            raise HarnessError("run id must be 6-16 lowercase letters or digits")

    @property
    def issuer(self) -> str:
        return f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"

    def sibling_issuer(self, pool_suffix: str) -> str:
        """Another (non-existent) pool's issuer in the same region."""
        return f"https://cognito-idp.{self.region}.amazonaws.com/{self.region}_{pool_suffix}"

    @property
    def discovery_uri(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    @property
    def run_prefix(self) -> str:
        return f"{USER_PREFIX}{self.run_id}-"

    def username(self, key: str) -> str:
        return f"{self.run_prefix}{key}"

    def settings(self, issuer: str | None = None) -> Settings:
        return Settings(
            oidc_issuer=issuer or self.issuer,
            oidc_client_ids=self.app_client_id,
            oidc_audience="",
            tenant_allowlist=TENANT_ALLOWLIST,
            oidc_leeway_seconds=self.leeway_seconds,
            oidc_jwks_cache_ttl_seconds=self.jwks_cache_ttl_seconds,
            oidc_jwks_refresh_cooldown_seconds=self.jwks_refresh_cooldown_seconds,
        )


def new_run_id() -> str:
    return secrets.token_hex(4)


# --- secret registry ----------------------------------------------------------------


class SecretRegistry:
    """Values that must never appear in logs or evidence. Never exposes them."""

    def __init__(self) -> None:
        self._values: set[str] = set()

    def add(self, value: str | None) -> None:
        if not value or len(value) < 8:
            return
        self._values.add(value)
        parts = value.split(".")
        if len(parts) == 3:
            self._values.update(p for p in parts if len(p) >= 16)

    def count_in(self, text: str) -> int:
        return sum(1 for v in self._values if v in text)

    def __len__(self) -> int:
        return len(self._values)

    def self_test(self) -> bool:
        """Positive control: the detector finds a registered value."""
        sample = next(iter(self._values), None)
        return sample is not None and self.count_in(f"<{sample}>") > 0


def leak_findings(text: str, registry: SecretRegistry) -> dict[str, int]:
    return {
        "registered_values": registry.count_in(text),
        "jwt_shaped": len(JWT_SHAPE.findall(text)),
        "bearer_prefix": text.count("Bearer "),
    }


def new_password() -> str:
    """Meets the pool policy (24+ chars, all classes); exists only in memory."""
    alphabet = string.ascii_letters + string.digits + "!#%*+-=?@^_"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(40))
        if (
            any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value)
            and any(not c.isalnum() for c in value)
        ):
            return value


# --- Cognito administration -----------------------------------------------------------


@dataclass
class Tokens:
    access: str
    id: str
    refresh: str


def _error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if isinstance(code, str):
            return code
    return type(exc).__name__


class CognitoAdmin:
    """The only code that talks to cognito-idp. ``client`` is a boto3 client."""

    def __init__(self, client: Any, config: HarnessConfig) -> None:
        self._client = client
        self._config = config

    @property
    def pool(self) -> str:
        return self._config.user_pool_id

    def describe_pool(self) -> dict[str, Any]:
        pool: dict[str, Any] = self._client.describe_user_pool(UserPoolId=self.pool)["UserPool"]
        return pool

    def describe_client(self, client_id: str) -> dict[str, Any]:
        response = self._client.describe_user_pool_client(UserPoolId=self.pool, ClientId=client_id)
        return cast(dict[str, Any], response["UserPoolClient"])

    def create_user(self, username: str, password: str, groups: tuple[str, ...]) -> None:
        self._client.admin_create_user(
            UserPoolId=self.pool, Username=username, MessageAction="SUPPRESS"
        )
        self._client.admin_set_user_password(
            UserPoolId=self.pool, Username=username, Password=password, Permanent=True
        )
        for group in groups:
            self._client.admin_add_user_to_group(
                UserPoolId=self.pool, Username=username, GroupName=group
            )

    def authenticate(self, username: str, password: str, client_id: str) -> Tokens:
        response = self._client.admin_initiate_auth(
            UserPoolId=self.pool,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
        if response.get("ChallengeName"):
            raise HarnessError("unexpected authentication challenge")
        result = response["AuthenticationResult"]
        return Tokens(result["AccessToken"], result["IdToken"], result["RefreshToken"])

    def refresh(self, refresh_token: str, client_id: str) -> str:
        response = self._client.admin_initiate_auth(
            UserPoolId=self.pool,
            ClientId=client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
        )
        return cast(str, response["AuthenticationResult"]["AccessToken"])

    def remove_from_group(self, username: str, group: str) -> None:
        self._client.admin_remove_user_from_group(
            UserPoolId=self.pool, Username=username, GroupName=group
        )

    def global_sign_out(self, username: str) -> None:
        self._client.admin_user_global_sign_out(UserPoolId=self.pool, Username=username)

    def delete_user(self, username: str) -> str:
        try:
            self._client.admin_delete_user(UserPoolId=self.pool, Username=username)
        except Exception as exc:
            if _error_code(exc) == "UserNotFoundException":
                return "already_absent"
            raise
        return "deleted"

    def user_exists(self, username: str) -> bool:
        try:
            self._client.admin_get_user(UserPoolId=self.pool, Username=username)
        except Exception as exc:
            if _error_code(exc) == "UserNotFoundException":
                return False
            raise
        return True

    def list_usernames(self, prefix: str) -> list[str]:
        names: list[str] = []
        kwargs: dict[str, Any] = {
            "UserPoolId": self.pool,
            "Filter": f'username ^= "{prefix}"',
            "Limit": 60,
        }
        while True:
            response = self._client.list_users(**kwargs)
            names.extend(u["Username"] for u in response.get("Users", []))
            token = response.get("PaginationToken")
            if not token:
                return sorted(n for n in names if n.startswith(prefix))
            kwargs["PaginationToken"] = token


def verify_caller_account(sts_client: Any, config: HarnessConfig) -> dict[str, Any]:
    """Fail closed unless the credentials are a role session in the expected account.

    Must run before the first Cognito call and before output capture (a credential
    provider may prompt for an MFA code). Raises GuardError with a reason code only:
    the observed ARN, account and session name are never echoed or stored.
    """
    try:
        return verify_assumed_role(
            sts_client, account_id=config.expected_account_id, role_name=config.expected_role_name
        )
    except IdentityGuardError as exc:
        raise GuardError(str(exc)) from None


def guard_evaluation_pool(admin: CognitoAdmin, config: HarnessConfig) -> dict[str, Any]:
    """Refuse to touch any pool that is not the tagged, temporary evaluation pool."""
    pool = admin.describe_pool()
    tags = pool.get("UserPoolTags") or {}
    problems = []
    expected_arn = (
        f"arn:aws:cognito-idp:{config.region}:{config.expected_account_id}"
        f":userpool/{config.user_pool_id}"
    )
    if pool.get("Arn") != expected_arn:
        problems.append("pool_arn")
    if not str(pool.get("Name", "")).startswith(POOL_NAME_PREFIX):
        problems.append("pool_name")
    problems += [f"tag:{k}" for k, v in REQUIRED_POOL_TAGS.items() if tags.get(k) != v]
    if pool.get("DeletionProtection") == "ACTIVE":
        problems.append("deletion_protection")
    for label, client_id in (("app", config.app_client_id), ("other", config.other_client_id)):
        client = admin.describe_client(client_id)
        if client.get("ClientSecret"):
            problems.append(f"{label}_client_has_secret")
        if "ALLOW_ADMIN_USER_PASSWORD_AUTH" not in (client.get("ExplicitAuthFlows") or []):
            problems.append(f"{label}_client_admin_auth_disabled")
    if problems:
        raise GuardError("not the M8.5 evaluation pool: " + ",".join(sorted(problems)))
    return {"pool_name_prefix": POOL_NAME_PREFIX, "required_tags_present": True}


# --- manifest and cleanup -----------------------------------------------------------


class Manifest:
    """Usernames only, written BEFORE each user is created (intent log)."""

    def __init__(self, path: Path, config: HarnessConfig) -> None:
        self.path = path
        self._config = config
        self.users: list[str] = []
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("user_pool_id") != config.user_pool_id:
                raise HarnessError("manifest belongs to a different user pool")
            self.users = [u for u in data.get("users", []) if u.startswith(config.run_prefix)]

    def record(self, username: str) -> None:
        if username not in self.users:
            self.users.append(username)
        self._write("in_progress")

    def close(self, verified: bool) -> None:
        if verified:
            self.path.unlink(missing_ok=True)
        else:
            self._write("cleanup_unverified")

    def _write(self, status: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "run_id": self._config.run_id,
            "region": self._config.region,
            "user_pool_id": self._config.user_pool_id,
            "status": status,
            "users": self.users,
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.path)


def cleanup_users(admin: CognitoAdmin, known: list[str], prefix: str) -> dict[str, Any]:
    """Delete known and listed users, then prove absence independently."""
    report: dict[str, Any] = {
        "prefix": prefix,
        "deleted": [],
        "already_absent": [],
        "errors": [],
        "remaining_listed": [],
        "remaining_get_user": [],
        "verification_errors": [],
        "interrupted": False,
    }
    targets = set(known)
    try:
        targets.update(admin.list_usernames(prefix))
    except Exception as exc:
        report["verification_errors"].append({"step": "list_before", "error": _error_code(exc)})
    for username in sorted(targets):
        try:
            report[admin.delete_user(username)].append(username)
        except KeyboardInterrupt:
            report["interrupted"] = True
            break
        except Exception as exc:
            report["errors"].append({"user": username, "error": _error_code(exc)})
    try:
        report["remaining_listed"] = admin.list_usernames(prefix)
    except Exception as exc:
        report["verification_errors"].append({"step": "list_after", "error": _error_code(exc)})
    for username in sorted(targets):
        try:
            if admin.user_exists(username):
                report["remaining_get_user"].append(username)
        except Exception as exc:
            report["verification_errors"].append(
                {"step": "get_user", "user": username, "error": _error_code(exc)}
            )
    report["users_targeted"] = len(targets)
    report["verified"] = not (
        report["errors"]
        or report["remaining_listed"]
        or report["remaining_get_user"]
        or report["verification_errors"]
        or report["interrupted"]
    )
    return report


# --- HTTP (discovery, JWKS) and fetch counting ----------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def http_get_json(url: str) -> Any:
    if not url.startswith("https://"):
        raise HarnessError("only https URLs are fetched")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    with urllib.request.build_opener(_NoRedirect()).open(
        request, timeout=HTTP_TIMEOUT_SECONDS
    ) as response:
        return json.load(response)


@contextmanager
def count_fetches() -> Iterator[Counter[str]]:
    """Count every URL opened through urllib (PyJWT's JWKS fetch included)."""
    original = urllib.request.build_opener
    counts: Counter[str] = Counter()

    def counting_build_opener(*handlers: Any) -> Any:
        opener = original(*handlers)
        real_open = opener.open

        def open_(request: Any, *args: Any, **kwargs: Any) -> Any:
            url = request.full_url if isinstance(request, urllib.request.Request) else str(request)
            counts[url] += 1
            return real_open(request, *args, **kwargs)

        setattr(opener, "open", open_)  # noqa: B010
        return opener

    urllib.request.build_opener = counting_build_opener
    try:
        yield counts
    finally:
        urllib.request.build_opener = original


# --- verification helpers -------------------------------------------------------------


def production_verifier(settings: Settings) -> OidcVerifier:
    verifier = oidc.build_oidc_verifier(settings)
    if verifier is None:
        raise HarnessError("verifier not configured")
    return verifier


def verify_outcome(verifier: OidcVerifier, token: str) -> tuple[str, VerifiedPrincipal | None]:
    """('ok', principal) or a bounded reason; never raises for auth failures."""
    try:
        return "ok", verifier.verify(token)
    except AuthenticationError as exc:
        return exc.reason.value, None
    except AuthenticationUnavailableError as exc:
        return f"unavailable:{exc.reason}", None


def map_outcome(principal: VerifiedPrincipal) -> tuple[str, TenantContext | None]:
    try:
        return "ok", map_principal(principal, frozenset(TENANT_ALLOWLIST.split(",")))
    except IdentityMappingError as exc:
        return exc.reason, None


def unverified_claims(token: str) -> dict[str, Any]:
    """Claim inspection for EVIDENCE SHAPE only, after verification already ran."""
    claims: dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
    return claims


def _b64(value: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def tamper_payload(token: str, groups: list[str]) -> str:
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["cognito:groups"] = groups
    return f"{header}.{_b64(claims)}.{signature}"


def resign_with_foreign_key(token: str) -> str:
    claims = unverified_claims(token)
    kid = jwt.get_unverified_header(token)["kid"]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def unsigned_token(token: str) -> str:
    kid = jwt.get_unverified_header(token)["kid"]
    header = _b64({"alg": "none", "typ": "JWT", "kid": kid})
    return f"{header}.{_b64(unverified_claims(token))}."


def hs256_token(token: str) -> str:
    """Algorithm-confusion attempt: HMAC with a throwaway secret under the real kid."""
    kid = jwt.get_unverified_header(token)["kid"]
    return jwt.encode(
        unverified_claims(token), secrets.token_bytes(32), algorithm="HS256", headers={"kid": kid}
    )


def foreign_kid_token(token: str, kid: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return jwt.encode(unverified_claims(token), key, algorithm="RS256", headers={"kid": kid})


# --- in-process application probe -----------------------------------------------------


class _FakeModel:
    """Stands in for Bedrock; records only whether and with what prompt it was called."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def converse(self, **kwargs: Any) -> dict[str, Any]:
        self.prompts.append(kwargs["messages"][0]["content"][0]["text"])
        return {
            "output": {"message": {"content": [{"text": "SYNTHETIC answer [1]"}]}},
            "usage": {"inputTokens": 1, "outputTokens": 1},
        }


class _FixedEmbeddings:
    def __init__(self, dimensions: int) -> None:
        self._vector = [1.0] + [0.0] * (dimensions - 1)

    def embed(self, text: str) -> list[float]:
        return list(self._vector)


class _EchoStore:
    """Returns one synthetic chunk for whichever tenant the context names."""

    def __init__(self) -> None:
        self.contexts: list[tuple[str, str]] = []

    def search(self, embedding: list[float], context: TenantContext, **_: Any) -> list[Any]:
        from app.rag.retrieval import RetrievedChunk

        self.contexts.append((context.tenant_id, context.role.value))
        return [
            RetrievedChunk(
                source=f"{context.tenant_id}.md",
                chunk_index=0,
                content=f"SYNTHETIC {context.tenant_id} content",
                score=1.0,
                document_id="m85",
                tenant_id=context.tenant_id,
            )
        ]


@dataclass
class ProbeResult:
    status: int
    body: Any
    contexts: list[tuple[str, str]]
    model_calls: int
    prompts: list[str]


class AppProbe:
    """Drives the real FastAPI app in-process with a given verifier and settings."""

    def __init__(self, settings: Settings, store: Any | None = None, dimensions: int = 4) -> None:
        self._settings = settings
        self._store = store
        self._dimensions = dimensions

    def call(
        self,
        verifier: OidcVerifier,
        path: str,
        token: str | None,
        extra_headers: dict[str, str] | None = None,
    ) -> ProbeResult:
        from fastapi.testclient import TestClient

        from app.api.dependencies import get_bedrock_service, get_rag_service
        from app.clients.bedrock import BedrockService
        from app.core.config import get_settings
        from app.main import app
        from app.rag.service import RagService

        model = _FakeModel()
        bedrock = BedrockService(client=model)
        store = self._store if self._store is not None else _EchoStore()
        service = RagService(
            bedrock=bedrock,
            embeddings=cast(Any, _FixedEmbeddings(self._dimensions)),
            store=cast(Any, store),
        )
        headers = dict(extra_headers or {})
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        body = {"question": "M8.5 probe"} if path == "/v1/query" else {"prompt": "M8.5 probe"}
        prior = oidc.get_oidc_verifier
        setattr(oidc, "get_oidc_verifier", lambda: verifier)  # noqa: B010
        app.dependency_overrides[get_settings] = lambda: self._settings
        app.dependency_overrides[get_rag_service] = lambda: service
        app.dependency_overrides[get_bedrock_service] = lambda: bedrock
        try:
            response = TestClient(app, raise_server_exceptions=False).post(
                path, json=body, headers=headers
            )
        finally:
            setattr(oidc, "get_oidc_verifier", prior)  # noqa: B010
            for dependency in (get_settings, get_rag_service, get_bedrock_service):
                app.dependency_overrides.pop(dependency, None)
        try:
            payload = response.json()
        except ValueError:
            payload = None
        contexts = list(store.contexts) if isinstance(store, _EchoStore) else []
        return ProbeResult(
            response.status_code, payload, contexts, len(model.prompts), model.prompts
        )


# --- the run --------------------------------------------------------------------------


@dataclass
class CaseResult:
    id: str
    title: str
    status: str
    expected: str
    observed: dict[str, Any] = field(default_factory=dict)
    note: str = ""


@dataclass
class RlsOptions:
    database_url: str
    dimensions: int = 4


class LiveRun:
    def __init__(
        self,
        config: HarnessConfig,
        admin: CognitoAdmin,
        manifest: Manifest,
        *,
        rls: RlsOptions | None = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.admin = admin
        self.manifest = manifest
        self.rls = rls
        self.sleep = sleep
        self.now = now
        self.registry = SecretRegistry()
        self.settings = config.settings()
        self.verifier = production_verifier(self.settings)
        self.probe = AppProbe(self.settings)
        self.passwords: dict[str, str] = {}
        self.tokens: dict[str, Tokens] = {}
        self.other_client_tokens: Tokens | None = None
        self.jwks_keys: list[dict[str, Any]] = []

    # setup ----------------------------------------------------------------------------

    def provision(self) -> None:
        for key, groups in USERS.items():
            username = self.config.username(key)
            password = new_password()
            self.registry.add(password)
            self.passwords[key] = password
            self.manifest.record(username)  # before creation: recoverable if interrupted
            self.admin.create_user(username, password, groups)

    def sign_in(self, key: str, client_id: str | None = None) -> Tokens:
        tokens = self.admin.authenticate(
            self.config.username(key), self.passwords[key], client_id or self.config.app_client_id
        )
        for value in (tokens.access, tokens.id, tokens.refresh):
            self.registry.add(value)
        return tokens

    def authenticate_all(self) -> None:
        # The expiry token is minted first so R-10 waits the least.
        self.tokens["expiry"] = self.sign_in("expiry")
        for key in USERS:
            if key != "expiry":
                self.tokens[key] = self.sign_in(key)
        self.other_client_tokens = self.sign_in("reader-a", self.config.other_client_id)

    def _register_principal(self, principal: VerifiedPrincipal | None) -> None:
        if principal is not None:
            self.registry.add(principal.sub)

    def _verify(self, verifier: OidcVerifier, token: str) -> tuple[str, VerifiedPrincipal | None]:
        outcome, principal = verify_outcome(verifier, token)
        self._register_principal(principal)
        return outcome, principal

    # cases ----------------------------------------------------------------------------

    def r01_discovery(self) -> CaseResult:
        doc = http_get_json(self.config.discovery_uri)
        observed = {
            "issuer_matches": doc.get("issuer") == self.config.issuer,
            "jwks_uri_matches_derived": doc.get("jwks_uri") == self.verifier_config.jwks_uri,
            "id_token_signing_algs": sorted(doc.get("id_token_signing_alg_values_supported", [])),
        }
        ok = (
            observed["issuer_matches"]
            and observed["jwks_uri_matches_derived"]
            and "RS256" in observed["id_token_signing_algs"]
        )
        return CaseResult(
            "R-01",
            "Issuer discovery",
            PASS if ok else FAIL,
            "issuer and jwks_uri match configuration; RS256 advertised",
            observed,
        )

    @property
    def verifier_config(self) -> OidcConfig:
        config = OidcConfig.from_settings(self.settings)
        assert config is not None
        return config

    def r02_jwks(self) -> CaseResult:
        data = http_get_json(self.verifier_config.jwks_uri)
        keys = data.get("keys", []) if isinstance(data, dict) else []
        self.jwks_keys = [k for k in keys if isinstance(k, dict)]
        kids = [k.get("kid") for k in self.jwks_keys]
        try:
            TrustedJwksClient._require_signing_keys(data)
            accepted = True
        except Exception:
            accepted = False
        observed: dict[str, Any] = {
            "key_count": len(self.jwks_keys),
            "kty": sorted({str(k.get("kty")) for k in self.jwks_keys}),
            "alg": sorted({str(k.get("alg")) for k in self.jwks_keys}),
            "use": sorted({str(k.get("use")) for k in self.jwks_keys}),
            "kids_unique": len(kids) == len(set(kids)),
            "accepted_by_verifier_validation": accepted,
        }
        ok = (
            observed["key_count"] >= 2
            and observed["kty"] == ["RSA"]
            and observed["alg"] == ["RS256"]
            and observed["use"] == ["sig"]
            and observed["kids_unique"]
            and accepted
        )
        return CaseResult(
            "R-02",
            "Real JWKS shape",
            PASS if ok else FAIL,
            ">=2 unique RSA RS256 sig keys accepted by verifier validation",
            observed,
        )

    def r03_valid_access_token(self) -> CaseResult:
        token = self.tokens["reader-a"].access
        outcome, principal = self._verify(self.verifier, token)
        observed: dict[str, Any] = {"verify": outcome}
        if principal is not None:
            mapping, context = map_outcome(principal)
            claims = unverified_claims(token)
            observed.update(
                {
                    "claim_names": sorted(claims),
                    "token_use": claims.get("token_use"),
                    "aud_present": "aud" in claims,
                    "client_id_is_app_client": claims.get("client_id") == self.config.app_client_id,
                    "groups": sorted(claims.get("cognito:groups", [])),
                    "access_token_lifetime_seconds": int(claims["exp"]) - int(claims["iat"]),
                    "mapping": mapping,
                    "tenant": context.tenant_id if context else None,
                    "role": context.role.value if context else None,
                }
            )
        http = self.probe.call(self.verifier, "/v1/query", token)
        observed.update({"http_status": http.status, "store_contexts": http.contexts})
        ok = (
            outcome == "ok"
            and observed.get("tenant") == "tenant-a"
            and observed.get("role") == "reader"
            and observed.get("token_use") == "access"
            and observed.get("aud_present") is False
            and observed.get("client_id_is_app_client") is True
            and observed.get("access_token_lifetime_seconds")
            == self.config.expected_access_token_lifetime
            and http.status == 200
            and http.contexts == [("tenant-a", "reader")]
        )
        return CaseResult(
            "R-03",
            "Valid Cognito access token",
            PASS if ok else FAIL,
            "verifies; tenant-a/reader; token_use=access; no aud; 200 as tenant-a",
            observed,
        )

    def r04_roles(self) -> CaseResult:
        admin = self.probe.call(self.verifier, "/v1/generate", self.tokens["admin-a"].access)
        ingestor_query = self.probe.call(
            self.verifier, "/v1/query", self.tokens["ingestor-b"].access
        )
        ingestor_generate = self.probe.call(
            self.verifier, "/v1/generate", self.tokens["ingestor-b"].access
        )
        observed = {
            "admin_a_generate": admin.status,
            "admin_a_model_calls": admin.model_calls,
            "ingestor_b_query": ingestor_query.status,
            "ingestor_b_contexts": ingestor_query.contexts,
            "ingestor_b_generate": ingestor_generate.status,
            "ingestor_b_generate_model_calls": ingestor_generate.model_calls,
        }
        ok = (
            admin.status == 200
            and admin.model_calls == 1
            and ingestor_query.status == 200
            and ingestor_query.contexts == [("tenant-b", "ingestor")]
            and ingestor_generate.status == 403
            and ingestor_generate.model_calls == 0
        )
        return CaseResult(
            "R-04",
            "Role and tenant from real groups",
            PASS if ok else FAIL,
            "admin-a generate 200; ingestor-b query 200 as tenant-b; ingestor generate 403",
            observed,
        )

    def r05_id_token(self) -> CaseResult:
        token = self.tokens["reader-a"].id
        outcome, _ = self._verify(self.verifier, token)
        claims = unverified_claims(token)
        http = self.probe.call(self.verifier, "/v1/query", token)
        observed = {
            "reason": outcome,
            "id_token_token_use": claims.get("token_use"),
            "id_token_has_client_id": "client_id" in claims,
            "http_status": http.status,
            "http_body_generic": http.body == GENERIC_BODIES[401],
        }
        ok = outcome in ("missing_claim", "wrong_token_use") and http.status == 401
        return CaseResult(
            "R-05",
            "ID token rejected",
            PASS if ok else FAIL,
            "401 missing_claim (no client_id) or wrong_token_use",
            observed,
        )

    def r06_wrong_client(self) -> CaseResult:
        assert self.other_client_tokens is not None
        token = self.other_client_tokens.access
        outcome, _ = self._verify(self.verifier, token)
        http = self.probe.call(self.verifier, "/v1/query", token)
        observed = {"reason": outcome, "http_status": http.status}
        ok = outcome == "wrong_client" and http.status == 401
        return CaseResult(
            "R-06",
            "Token from a non-allowlisted client",
            PASS if ok else FAIL,
            "401 wrong_client",
            observed,
        )

    def r07_tampering(self) -> CaseResult:
        source = self.tokens["reader-a"].access
        variants = {
            "payload_swapped": (
                tamper_payload(source, ["tenant:tenant-b", "role:admin"]),
                "invalid_signature",
            ),
            "resigned_foreign_key": (resign_with_foreign_key(source), "invalid_signature"),
            # Empty signature segment: rejected structurally before the alg check.
            "alg_none_empty_signature": (unsigned_token(source), "malformed_token"),
            "alg_none_with_signature": (unsigned_token(source) + "c2ln", "invalid_algorithm"),
            "alg_hs256_confusion": (hs256_token(source), "invalid_algorithm"),
        }
        observed: dict[str, Any] = {}
        ok = True
        for name, (token, expected) in variants.items():
            self.registry.add(token)
            outcome, _ = self._verify(self.verifier, token)
            http = self.probe.call(self.verifier, "/v1/generate", token)
            observed[name] = {"reason": outcome, "http_status": http.status}
            ok = ok and outcome == expected and http.status == 401 and http.model_calls == 0
        return CaseResult(
            "R-07",
            "Tampered tokens",
            PASS if ok else FAIL,
            "payload swap / foreign re-sign -> invalid_signature; alg=none with empty "
            "signature -> malformed_token; alg=none or HS256 -> invalid_algorithm",
            observed,
        )

    def r08_group_mapping(self) -> CaseResult:
        expected = {
            "nogroups": "identity_mapping_denied",
            "two-tenants": "identity_mapping_denied",
            "tenant-only": "identity_mapping_denied",
            "unknown-tenant": "unknown_tenant",
        }
        observed: dict[str, Any] = {}
        ok = True
        for key, reason in expected.items():
            token = self.tokens[key].access
            outcome, principal = self._verify(self.verifier, token)
            mapping = map_outcome(principal)[0] if principal is not None else outcome
            http = self.probe.call(self.verifier, "/v1/query", token)
            claims = unverified_claims(token)
            observed[key] = {
                "verify": outcome,
                "groups_claim_present": "cognito:groups" in claims,
                "groups": sorted(claims.get("cognito:groups", [])),
                "mapping": mapping,
                "http_status": http.status,
                "http_body_generic": http.body == GENERIC_BODIES[403],
            }
            ok = ok and outcome == "ok" and mapping == reason and http.status == 403
        return CaseResult(
            "R-08",
            "Missing or ambiguous tenant/role groups",
            PASS if ok else FAIL,
            "authentic tokens; 403 identity_mapping_denied / unknown_tenant",
            observed,
        )

    def r09_wrong_issuer(self) -> CaseResult:
        """Signature verifies against the REAL keys; only the issuer differs.

        The JWKS client is pointed at the real pool's key set while the
        configured issuer names another pool, so a pass proves an issuer
        rejection - not an unreachable endpoint (which is R-13).
        """
        wrong = self.config.sibling_issuer("M85OtherIssuer")
        real = self.verifier_config
        config = OidcConfig(
            issuer=wrong,
            client_ids=real.client_ids,
            audience=None,
            leeway_seconds=real.leeway_seconds,
            jwks_cache_ttl_seconds=real.jwks_cache_ttl_seconds,
            jwks_refresh_cooldown_seconds=real.jwks_refresh_cooldown_seconds,
        )
        jwks = TrustedJwksClient(
            real.jwks_uri,
            lifespan=real.jwks_cache_ttl_seconds,
            cooldown_duration=real.jwks_refresh_cooldown_seconds,
        )
        verifier = OidcVerifier(config, jwks)
        with count_fetches() as counts:
            outcome, _ = self._verify(verifier, self.tokens["reader-a"].access)
        observed = {
            "reason": outcome,
            "real_jwks_fetches": counts[real.jwks_uri],
            "jwks_available": not outcome.startswith("unavailable"),
            "control_correct_issuer_accepts": self._verify(
                self.verifier, self.tokens["reader-a"].access
            )[0]
            == "ok",
        }
        ok = (
            outcome == "wrong_issuer"
            and counts[real.jwks_uri] >= 1
            and observed["control_correct_issuer_accepts"]
        )
        return CaseResult(
            "R-09",
            "Wrong issuer with a reachable, valid key set",
            PASS if ok else FAIL,
            "401 wrong_issuer after a successful real JWKS fetch; control accepts",
            observed,
        )

    def r10_expired(self) -> CaseResult:
        if self.config.skip_expiry:
            return CaseResult(
                "R-10", "Expired token", SKIPPED, "401 expired_token", note="--skip-expiry"
            )
        token = self.tokens["expiry"].access
        exp = int(unverified_claims(token)["exp"])
        wait = exp + self.config.leeway_seconds + 2 - self.now()
        if wait > MAX_EXPIRY_WAIT_SECONDS:
            return CaseResult(
                "R-10", "Expired token", FAIL, "401 expired_token", {"wait_seconds": int(wait)}
            )
        self.sleep(max(0.0, wait))
        outcome, _ = self._verify(self.verifier, token)
        http = self.probe.call(self.verifier, "/v1/query", token)
        observed = {"reason": outcome, "http_status": http.status, "waited_seconds": int(wait)}
        ok = outcome == "expired_token" and http.status == 401
        return CaseResult(
            "R-10",
            "Expired token",
            PASS if ok else FAIL,
            "401 expired_token after exp + leeway",
            observed,
        )

    def r11_cache(self) -> CaseResult:
        verifier = production_verifier(self.settings)
        with count_fetches() as counts:
            token = self.tokens["reader-a"].access
            outcomes = {self._verify(verifier, token)[0] for _ in range(20)}
        fetches = counts[self.verifier_config.jwks_uri]
        observed = {"verifications": 20, "outcomes": sorted(outcomes), "jwks_fetches": fetches}
        ok = outcomes == {"ok"} and fetches == 1
        return CaseResult(
            "R-11", "JWKS cache", PASS if ok else FAIL, "20 verifications, 1 JWKS fetch", observed
        )

    def r12_unknown_kid(self) -> CaseResult:
        verifier = production_verifier(self.settings)
        source = self.tokens["reader-a"].access
        forged = foreign_kid_token(source, f"m85-unknown-kid-{self.config.run_id}")
        self.registry.add(forged)
        with count_fetches() as counts:
            first = self._verify(verifier, source)[0]
            reasons = [self._verify(verifier, forged)[0] for _ in range(5)]
            after = self._verify(verifier, source)[0]
        fetches = counts[self.verifier_config.jwks_uri]
        observed = {
            "valid_before": first,
            "unknown_kid_reasons": sorted(set(reasons)),
            "valid_after": after,
            "jwks_fetches": fetches,
        }
        ok = first == "ok" and set(reasons) == {"unknown_kid"} and after == "ok" and fetches <= 2
        return CaseResult(
            "R-12",
            "Unknown kid refresh is bounded",
            PASS if ok else FAIL,
            "401 unknown_kid; <=2 JWKS fetches across 7 verifications; valid token unaffected",
            observed,
        )

    def r13_jwks_unavailable(self) -> CaseResult:
        missing = self.config.sibling_issuer("M85NoSuchPool0")
        settings = self.config.settings(issuer=missing)
        verifier = production_verifier(settings)
        jwks_uri = f"{missing}/.well-known/jwks.json"
        token = self.tokens["reader-a"].access
        with count_fetches() as counts:
            reasons = [self._verify(verifier, token)[0] for _ in range(3)]
            http = AppProbe(settings).call(verifier, "/v1/query", token)
        observed = {
            "reasons": sorted(set(reasons)),
            "jwks_fetches": counts[jwks_uri],
            "http_status": http.status,
            "http_body_generic": http.body == GENERIC_BODIES[503],
        }
        ok = (
            set(reasons) == {"unavailable:jwks_unavailable"}
            and counts[jwks_uri] == 1
            and http.status == 503
            and observed["http_body_generic"]
        )
        return CaseResult(
            "R-13",
            "JWKS endpoint unavailable",
            PASS if ok else FAIL,
            "503 Authentication unavailable; failure backoff keeps it to 1 fetch",
            observed,
        )

    def r14_rotation(self) -> CaseResult:
        kids = {k.get("kid") for k in self.jwks_keys}
        access_kid = jwt.get_unverified_header(self.tokens["reader-a"].access).get("kid")
        id_kid = jwt.get_unverified_header(self.tokens["reader-a"].id).get("kid")
        return CaseResult(
            "R-14",
            "Signing key rotation",
            NOT_TESTABLE,
            "rotation cannot be triggered on a Cognito user pool",
            {
                "jwks_key_count": len(kids),
                "access_token_kid_published": access_kid in kids,
                "id_token_kid_published": id_kid in kids,
                "access_and_id_kids_differ": access_kid != id_kid,
            },
            note=(
                "Rotation, cache refresh and outage behavior are covered by "
                "app/tests/test_oidc_verification.py; live key selection by kid is R-02/R-12."
            ),
        )

    def r15_real_rls(self) -> CaseResult:
        if self.rls is None:
            return CaseResult(
                "R-15",
                "Real token through PostgreSQL RLS (optional)",
                SKIPPED,
                "tenant-a rows only",
                note="--rls-database-url not provided",
            )
        import psycopg

        from app.auth.permissions import Classification
        from app.rag.retrieval import VectorStore

        store = VectorStore(conninfo=self.rls.database_url)
        document_id = f"m85-live-{self.config.run_id}"
        vector = [1.0] + [0.0] * (self.rls.dimensions - 1)
        markers = {"tenant-a": "M85 SYNTHETIC A MARKER", "tenant-b": "M85 SYNTHETIC B MARKER"}
        try:
            for tenant, marker in markers.items():
                store.upsert_chunks(
                    tenant,
                    "m85.md",
                    Classification.INTERNAL,
                    [(0, marker, vector)],
                    document_id=document_id,
                    authorize_as=None,
                )
            probe = AppProbe(self.settings, store=store, dimensions=self.rls.dimensions)
            http = probe.call(
                self.verifier,
                "/v1/query",
                self.tokens["reader-a"].access,
                {"X-Tenant-Id": "tenant-b", "X-Tenant-Role": "admin"},
            )
            prompt = http.prompts[0] if http.prompts else ""
            observed = {
                "http_status": http.status,
                "own_marker_in_prompt": markers["tenant-a"] in prompt,
                "other_marker_in_prompt": markers["tenant-b"] in prompt,
            }
            ok = (
                http.status == 200
                and observed["own_marker_in_prompt"]
                and not observed["other_marker_in_prompt"]
            )
        finally:
            for tenant in markers:
                with psycopg.connect(self.rls.database_url) as conn, conn.cursor() as cur:
                    cur.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))
                    cur.execute(
                        "DELETE FROM document_chunks WHERE document_id = %s", (document_id,)
                    )
        return CaseResult(
            "R-15",
            "Real token through PostgreSQL RLS (optional)",
            PASS if ok else FAIL,
            "forged headers ignored; tenant-a rows only",
            observed,
        )

    def r16_group_removal(self) -> CaseResult:
        old = self.tokens["group-change"].access
        self.admin.remove_from_group(self.config.username("group-change"), "tenant:tenant-a")
        old_outcome, principal = self._verify(self.verifier, old)
        old_mapping = map_outcome(principal)[0] if principal is not None else old_outcome
        fresh = self.sign_in("group-change").access
        new_outcome, new_principal = self._verify(self.verifier, fresh)
        new_mapping = map_outcome(new_principal)[0] if new_principal is not None else new_outcome
        observed = {"old_token_mapping": old_mapping, "new_token_mapping": new_mapping}
        if new_mapping != "identity_mapping_denied":
            status = FAIL
        else:
            status = LIMITATION if old_mapping == "ok" else PASS
        return CaseResult(
            "R-16",
            "Group removed mid-session",
            status,
            "old token keeps the group until exp (documented); new token denied",
            observed,
            note="Stateless verification: group changes apply at next token issue (<=5 min).",
        )

    def r17_global_sign_out(self) -> CaseResult:
        tokens = self.tokens["sign-out"]
        self.admin.global_sign_out(self.config.username("sign-out"))
        access_outcome, _ = self._verify(self.verifier, tokens.access)
        try:
            refreshed = self.admin.refresh(tokens.refresh, self.config.app_client_id)
            self.registry.add(refreshed)
            refresh_result = "issued"
        except Exception as exc:
            refresh_result = _error_code(exc)
        observed = {"old_access_token": access_outcome, "refresh_after_sign_out": refresh_result}
        if refresh_result != "NotAuthorizedException":
            status = FAIL
        else:
            status = LIMITATION if access_outcome == "ok" else PASS
        return CaseResult(
            "R-17",
            "Global sign-out",
            status,
            "access token valid until exp (documented); refresh rejected",
            observed,
            note="Local JWT verification cannot observe revocation; bounded by token lifetime.",
        )

    def cases(self) -> list[Callable[[], CaseResult]]:
        return [
            self.r01_discovery,
            self.r02_jwks,
            self.r03_valid_access_token,
            self.r04_roles,
            self.r05_id_token,
            self.r06_wrong_client,
            self.r07_tampering,
            self.r08_group_mapping,
            self.r09_wrong_issuer,
            self.r11_cache,
            self.r12_unknown_kid,
            self.r13_jwks_unavailable,
            self.r14_rotation,
            self.r15_real_rls,
            self.r16_group_removal,
            self.r17_global_sign_out,
            self.r10_expired,  # last: waits for the expiry token to lapse
        ]


def r18_log_hygiene(captured: str, registry: SecretRegistry) -> CaseResult:
    findings = leak_findings(captured, registry)
    control = registry.self_test()
    ok = control and not any(findings.values())
    return CaseResult(
        "R-18",
        "No token or secret material in logs",
        PASS if ok else FAIL,
        "0 registered values, JWT-shaped strings or authorization-header values in output",
        {**findings, "registered_secret_count": len(registry), "detector_self_test": control},
    )


class _Tee(io.TextIOBase):
    def __init__(self, *streams: Any) -> None:
        self._streams = streams

    def write(self, text: str) -> int:
        for stream in self._streams:
            stream.write(text)
        return len(text)

    def flush(self) -> None:
        for stream in self._streams:
            stream.flush()


@contextmanager
def capture_output() -> Iterator[io.StringIO]:
    """Capture stdout, stderr and stdlib logging for the R-18 scan."""
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        with (
            redirect_stdout(cast(Any, _Tee(sys.stdout, buffer))),
            redirect_stderr(cast(Any, _Tee(sys.stderr, buffer))),
        ):
            yield buffer
    finally:
        root.removeHandler(handler)


def _safe_case(case: Callable[[], CaseResult]) -> CaseResult:
    try:
        return case()
    except (KeyboardInterrupt, GuardError):
        raise
    except Exception as exc:
        name = getattr(case, "__name__", "case")
        case_id = "R-" + name[1:3] if name.startswith("r") else name
        return CaseResult(case_id, name, ERROR, "case completed", {"error": _error_code(exc)})


def overall_status(run_status: str, cases: list[CaseResult], cleanup: dict[str, Any]) -> str:
    if not cleanup.get("verified", False):
        return "INCOMPLETE_CLEANUP"
    if run_status != "completed":
        return run_status.upper()
    if any(c.status in (FAIL, ERROR) for c in cases):
        return "FAIL"
    if any(c.status == SKIPPED and c.id not in OPTIONAL_CASES for c in cases):
        return "INCOMPLETE"
    return "PASS"


EXIT_CODES = {
    "PASS": 0,
    "FAIL": 1,
    "INCOMPLETE_CLEANUP": 2,
    "INTERRUPTED": 3,
    "INCOMPLETE": 3,
    "ERROR": 3,
    "GUARD_FAILED": 4,
}


def write_evidence(path: Path, document: dict[str, Any], registry: SecretRegistry) -> None:
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    findings = leak_findings(text, registry)
    if any(findings.values()):
        raise EvidenceLeakError(f"evidence refused: {findings}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def run(
    config: HarnessConfig,
    client: Any,
    *,
    sts_client: Any,
    evidence_path: Path,
    manifest_path: Path,
    rls: RlsOptions | None = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.time,
) -> tuple[int, dict[str, Any]]:
    account_guard = verify_caller_account(sts_client, config)  # before any Cognito call
    started = datetime.now(UTC).isoformat(timespec="seconds")
    admin = CognitoAdmin(client, config)
    manifest = Manifest(manifest_path, config)
    live = LiveRun(config, admin, manifest, rls=rls, sleep=sleep, now=now)
    cases: list[CaseResult] = []
    run_status = "completed"
    error: str | None = None
    guard: dict[str, Any] = {}
    cleanup: dict[str, Any] = {"verified": False}
    users_created = False
    with capture_output() as captured:
        try:
            guard = guard_evaluation_pool(admin, config)
            users_created = True
            live.provision()
            live.authenticate_all()
            for case in live.cases():
                cases.append(_safe_case(case))
        except GuardError as exc:
            run_status, error = "guard_failed", str(exc)
        except KeyboardInterrupt:
            run_status = "interrupted"
        except Exception as exc:
            run_status, error = "error", _error_code(exc)
        finally:
            if users_created or manifest.users:
                cleanup = cleanup_users(admin, manifest.users, config.run_prefix)
            else:
                cleanup = {"verified": True, "note": "guard refused the pool; no user created"}
            manifest.close(bool(cleanup.get("verified")))
    if cases:
        cases.append(r18_log_hygiene(captured.getvalue(), live.registry))
    status = overall_status(run_status, cases, cleanup)
    document = {
        "milestone": "M8.5",
        "harness": "evaluations/live/m8_5_cognito.py",
        "run_id": config.run_id,
        "started_utc": started,
        "finished_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "region": config.region,
        "user_pool_id": config.user_pool_id,
        "verifier": {
            "module": "app.auth.oidc.build_oidc_verifier",
            "algorithm": oidc.ALGORITHM,
            "required_claims": list(oidc.REQUIRED_CLAIMS),
            "leeway_seconds": config.leeway_seconds,
            "jwks_cache_ttl_seconds": config.jwks_cache_ttl_seconds,
            "jwks_refresh_cooldown_seconds": config.jwks_refresh_cooldown_seconds,
            "tenant_allowlist": TENANT_ALLOWLIST.split(","),
        },
        "account_guard": account_guard,
        "guard": guard,
        "run_status": run_status,
        "error": error,
        "overall": status,
        "cases": [asdict(c) for c in cases],
        "cleanup": cleanup,
        "evidence_policy": (
            "No tokens, passwords, subject identifiers or token segments are recorded; "
            "claim names, bounded reasons, status codes and synthetic group names only."
        ),
    }
    write_evidence(evidence_path, document, live.registry)
    return EXIT_CODES.get(status, 3), document


def cleanup_only(
    config: HarnessConfig, client: Any, *, sts_client: Any, manifest_path: Path, all_runs: bool
) -> tuple[int, dict[str, Any]]:
    """Recovery after an interrupted run: delete and verify, create nothing."""
    verify_caller_account(sts_client, config)  # before any Cognito call
    admin = CognitoAdmin(client, config)
    guard_evaluation_pool(admin, config)
    manifest = Manifest(manifest_path, config)
    prefix = USER_PREFIX if all_runs else config.run_prefix
    report = cleanup_users(admin, manifest.users, prefix)
    manifest.close(bool(report["verified"]))
    return (0 if report["verified"] else 2), report
