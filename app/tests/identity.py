"""Deterministic test identity provider (M8).

Generates RSA keys at runtime, serves them from an in-process JWKS transport
and mints synthetic Cognito-shaped access tokens. The verifier under test is
the production OidcVerifier with only the network transport replaced, so
every HTTP test exercises real signature and claim verification.

No real Cognito token, key or credential is used or committed.
"""
import json
import time
import uuid
from collections.abc import Iterator
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from app.auth import oidc

TEST_ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool"
TEST_CLIENT_ID = "test-app-client"
TEST_KID = "test-kid-1"


def new_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(key: RSAPrivateKey, kid: str) -> dict[str, Any]:
    jwk: dict[str, Any] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return jwk


class FakeJwks:
    """In-process JWKS endpoint: records every request and can simulate outages."""

    def __init__(self, keys: dict[str, RSAPrivateKey]) -> None:
        self.keys = dict(keys)
        self.requests: list[str] = []
        self.available = True

    def __call__(self, uri: str, timeout: float) -> dict[str, Any]:
        self.requests.append(uri)
        if not self.available:
            raise ConnectionError("simulated JWKS outage")
        return {"keys": [public_jwk(key, kid) for kid, key in self.keys.items()]}


TEST_CONFIG = oidc.OidcConfig(
    issuer=TEST_ISSUER,
    client_ids=frozenset({TEST_CLIENT_ID}),
    audience=None,
    leeway_seconds=30,
    jwks_cache_ttl_seconds=300,
    jwks_refresh_cooldown_seconds=30,
)

SIGNING_KEY = new_key()
FAKE_JWKS = FakeJwks({TEST_KID: SIGNING_KEY})
TEST_VERIFIER = oidc.OidcVerifier.from_config(TEST_CONFIG, transport=FAKE_JWKS)


def claims(
    groups: list[str] | None = None, *, lifetime: int = 3600, **overrides: Any
) -> dict[str, Any]:
    now = int(time.time())
    body: dict[str, Any] = {
        "sub": str(uuid.uuid4()),
        "iss": TEST_ISSUER,
        "client_id": TEST_CLIENT_ID,
        "token_use": "access",
        "scope": "aws.cognito.signin.user.admin",
        "auth_time": now,
        "iat": now,
        "exp": now + lifetime,
        "jti": str(uuid.uuid4()),
        "username": "synthetic-user",
    }
    if groups is not None:
        body["cognito:groups"] = groups
    body.update(overrides)
    return {k: v for k, v in body.items() if v is not ...}


def sign(
    body: dict[str, Any],
    *,
    key: RSAPrivateKey | None = None,
    kid: str = TEST_KID,
    headers: dict[str, Any] | None = None,
) -> str:
    return jwt.encode(
        body,
        key or SIGNING_KEY,
        algorithm="RS256",
        headers={"kid": kid, **(headers or {})},
    )


def access_token(tenant: str, role: str, **overrides: Any) -> str:
    return sign(claims([f"tenant:{tenant}", f"role:{role}"], **overrides))


def bearer(tenant: str, role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token(tenant, role)}"}


@pytest.fixture(autouse=True)
def install_test_verifier(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Route every app's identity resolution through the test issuer."""
    monkeypatch.setattr(oidc, "get_oidc_verifier", lambda: TEST_VERIFIER)
    yield
