"""Cryptographic verification of Cognito access tokens (M8, AUTHN-01..12).

Every test uses RSA keys generated at runtime and an in-process JWKS that
records each request. The verifier is the production OidcVerifier; only the
network transport is replaced. No real token, key or public network is used.
"""
import base64
import hashlib
import hmac
import io
import json
import time
import urllib.request
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from app.auth import oidc
from app.auth.oidc import AuthenticationError, AuthenticationUnavailableError, AuthFailure
from app.tests.identity import (
    SIGNING_KEY,
    TEST_CLIENT_ID,
    TEST_CONFIG,
    TEST_ISSUER,
    TEST_KID,
    FakeJwks,
    claims,
    new_key,
    public_jwk,
    sign,
)

GROUPS = ["tenant:tenant-a", "role:reader"]


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_verifier(
    keys: dict[str, Any] | None = None,
    *,
    clock: FakeClock | None = None,
    cooldown: int = 30,
    ttl: int = 300,
    audience: str | None = None,
) -> tuple[oidc.OidcVerifier, FakeJwks]:
    jwks = FakeJwks(keys if keys is not None else {TEST_KID: SIGNING_KEY})
    config = oidc.OidcConfig(
        issuer=TEST_ISSUER,
        client_ids=frozenset({TEST_CLIENT_ID}),
        audience=audience,
        leeway_seconds=30,
        jwks_cache_ttl_seconds=ttl,
        jwks_refresh_cooldown_seconds=cooldown,
    )
    client = oidc.TrustedJwksClient(
        config.jwks_uri,
        lifespan=ttl,
        cooldown_duration=cooldown,
        transport=jwks,
        clock=clock or time.monotonic,
    )
    return oidc.OidcVerifier(config, client), jwks


def reason(verifier: oidc.OidcVerifier, token: str) -> AuthFailure:
    with pytest.raises(AuthenticationError) as info:
        verifier.verify(token)
    return info.value.reason


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


# --- AUTHN-01 valid token -------------------------------------------------------


def test_authn_01_valid_access_token_is_accepted() -> None:
    verifier, _ = make_verifier()
    body = claims(GROUPS)
    principal = verifier.verify(sign(body))
    assert principal.sub == body["sub"]
    assert principal.client_id == TEST_CLIENT_ID
    assert principal.groups == tuple(GROUPS)
    assert body["sub"] not in repr(principal)


def test_expiry_within_leeway_is_accepted_beyond_it_rejected() -> None:
    verifier, _ = make_verifier()
    now = int(time.time())
    assert verifier.verify(sign(claims(GROUPS, iat=now - 600, exp=now - 10)))
    assert reason(verifier, sign(claims(GROUPS, iat=now - 600, exp=now - 60))) is (
        AuthFailure.EXPIRED_TOKEN
    )


# --- AUTHN-02/03/03b signature and algorithm ------------------------------------


def test_authn_02_tampered_payload_is_rejected() -> None:
    verifier, _ = make_verifier()
    header, payload, signature = sign(claims(GROUPS)).split(".")
    body = json.loads(unb64(payload))
    body["cognito:groups"] = ["tenant:tenant-a", "role:admin"]
    tampered = ".".join([header, b64(json.dumps(body).encode()), signature])
    assert reason(verifier, tampered) is AuthFailure.INVALID_SIGNATURE


def test_authn_03_other_private_key_with_trusted_kid_is_rejected() -> None:
    verifier, _ = make_verifier()
    forged = sign(claims(GROUPS), key=new_key(), kid=TEST_KID)
    assert reason(verifier, forged) is AuthFailure.INVALID_SIGNATURE


def test_authn_03b_algorithm_confusion_and_none_are_rejected_without_network() -> None:
    verifier, jwks = make_verifier()
    body = claims(GROUPS)
    payload = b64(json.dumps(body).encode())

    def token(header: dict[str, Any], signature: str) -> str:
        return ".".join([b64(json.dumps(header).encode()), payload, signature])

    public_pem = SIGNING_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hs_header = {"alg": "HS256", "kid": TEST_KID, "typ": "JWT"}
    signing_input = f"{b64(json.dumps(hs_header).encode())}.{payload}".encode()
    hs_signature = b64(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
    attempts = {
        "hs256_with_public_key": token(hs_header, hs_signature),
        "alg_none": token({"alg": "none", "kid": TEST_KID}, "AAAA"),
        "alg_none_unsigned": token({"alg": "none", "kid": TEST_KID}, ""),
        "rs512": jwt.encode(body, SIGNING_KEY, algorithm="RS512", headers={"kid": TEST_KID}),
        "missing_alg": token({"kid": TEST_KID}, "AAAA"),
    }
    for name, attempt in attempts.items():
        assert reason(verifier, attempt) in {
            AuthFailure.INVALID_ALGORITHM,
            AuthFailure.MALFORMED_TOKEN,
        }, name
    assert jwks.requests == []


# --- AUTHN-04..07 claims ----------------------------------------------------------


def test_authn_04_expired_token_is_rejected() -> None:
    verifier, _ = make_verifier()
    now = int(time.time())
    assert reason(verifier, sign(claims(GROUPS, iat=now - 7200, exp=now - 3600))) is (
        AuthFailure.EXPIRED_TOKEN
    )


def test_future_iat_and_nbf_are_rejected() -> None:
    verifier, _ = make_verifier()
    now = int(time.time())
    assert reason(verifier, sign(claims(GROUPS, nbf=now + 3600))) is (
        AuthFailure.TOKEN_NOT_YET_VALID
    )
    assert reason(verifier, sign(claims(GROUPS, iat=now + 3600, exp=now + 7200))) in {
        AuthFailure.TOKEN_NOT_YET_VALID,
        AuthFailure.INVALID_TOKEN,
    }


@pytest.mark.parametrize(
    "issuer",
    [
        "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_OtherPool",
        TEST_ISSUER + "/",
        TEST_ISSUER.replace("https://", "http://"),
        "https://evil.example/us-east-1_TestPool",
    ],
)
def test_authn_05_wrong_issuer_is_rejected(issuer: str) -> None:
    verifier, _ = make_verifier()
    assert reason(verifier, sign(claims(GROUPS, iss=issuer))) is AuthFailure.WRONG_ISSUER


def test_authn_06_wrong_or_missing_client_is_rejected() -> None:
    verifier, _ = make_verifier()
    assert reason(verifier, sign(claims(GROUPS, client_id="other-app"))) is (
        AuthFailure.WRONG_CLIENT
    )
    assert reason(verifier, sign(claims(GROUPS, client_id=...))) is AuthFailure.MISSING_CLAIM
    assert reason(verifier, sign(claims(GROUPS, client_id=["test-app-client"]))) is (
        AuthFailure.WRONG_CLIENT
    )


def test_authn_07_id_token_is_rejected() -> None:
    verifier, _ = make_verifier()
    id_token = claims(GROUPS, token_use="id", aud=TEST_CLIENT_ID, client_id=...)  # noqa: S106
    assert reason(verifier, sign(id_token)) in {
        AuthFailure.WRONG_TOKEN_USE,
        AuthFailure.MISSING_CLAIM,
    }
    id_use = sign(claims(GROUPS, token_use="id"))  # noqa: S106 - claim value, not a secret
    assert reason(verifier, id_use) is AuthFailure.WRONG_TOKEN_USE


@pytest.mark.parametrize("missing", ["exp", "iat", "iss", "sub", "token_use", "client_id"])
def test_every_required_claim_is_enforced(missing: str) -> None:
    verifier, _ = make_verifier()
    removed: dict[str, Any] = {missing: ...}
    assert reason(verifier, sign(claims(GROUPS, **removed))) is AuthFailure.MISSING_CLAIM


def test_empty_or_non_string_subject_is_rejected() -> None:
    verifier, _ = make_verifier()
    for bad in ("", 123):
        assert reason(verifier, sign(claims(GROUPS, sub=bad))) in {
            AuthFailure.MISSING_CLAIM,
            AuthFailure.INVALID_TOKEN,
        }


def test_audience_is_checked_only_when_configured() -> None:
    plain, _ = make_verifier()
    assert plain.verify(sign(claims(GROUPS, aud="https://api.example")))
    bound, _ = make_verifier(audience="https://api.example")
    assert bound.verify(sign(claims(GROUPS, aud="https://api.example")))
    assert reason(bound, sign(claims(GROUPS, aud="https://other.example"))) is (
        AuthFailure.WRONG_AUDIENCE
    )
    assert reason(bound, sign(claims(GROUPS))) in {
        AuthFailure.WRONG_AUDIENCE,
        AuthFailure.MISSING_CLAIM,
    }


# --- AUTHN-08 malformed -----------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "",
        "abc",
        "a.b",
        "a.b.c.d",
        "..",
        "!!!.@@@.###",
        b64(b"not json") + ".e30.sig",
        b64(json.dumps({"alg": "RS256"}).encode()) + ".e30.sig",
        b64(json.dumps({"alg": "RS256", "kid": 7}).encode()) + ".e30.sig",
        b64(json.dumps({"alg": "RS256", "kid": "k" * 300}).encode()) + ".e30.sig",
        "x" * (oidc.MAX_TOKEN_CHARS + 1),
    ],
)
def test_authn_08_malformed_tokens_are_rejected_without_network(token: str) -> None:
    verifier, jwks = make_verifier()
    assert reason(verifier, token) is AuthFailure.MALFORMED_TOKEN
    assert jwks.requests == []


def test_payload_that_is_not_json_is_rejected() -> None:
    verifier, _ = make_verifier()
    header = b64(json.dumps({"alg": "RS256", "kid": TEST_KID}).encode())
    assert reason(verifier, f"{header}.{b64(b'not json')}.AAAA") in {
        AuthFailure.MALFORMED_TOKEN,
        AuthFailure.INVALID_SIGNATURE,
    }


# --- AUTHN-09/10 key lookup, rotation and bounded refresh -----------------------


def test_authn_09_unknown_kid_is_rejected_and_refresh_is_bounded() -> None:
    verifier, jwks = make_verifier()
    verifier.verify(sign(claims(GROUPS)))
    assert len(jwks.requests) == 1
    rogue = new_key()
    for i in range(50):
        token = sign(claims(GROUPS), key=rogue, kid=f"random-kid-{i}")
        assert reason(verifier, token) is AuthFailure.UNKNOWN_KID
    # A random-kid flood inside the cooldown causes no extra JWKS request.
    assert len(jwks.requests) == 1


def test_authn_10_rotated_key_is_used_after_one_bounded_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    monkeypatch.setattr(time, "monotonic", clock)
    verifier, jwks = make_verifier(clock=clock)
    verifier.verify(sign(claims(GROUPS)))
    rotated = new_key()
    jwks.keys = {"rotated-kid": rotated}
    token = sign(claims(GROUPS), key=rotated, kid="rotated-kid")
    # Inside the cooldown the new kid is not fetched yet.
    assert reason(verifier, token) is AuthFailure.UNKNOWN_KID
    assert len(jwks.requests) == 1
    clock.now += 31
    assert verifier.verify(token).groups == tuple(GROUPS)
    assert len(jwks.requests) == 2
    # The retired key is no longer trusted once the set has been refreshed.
    assert reason(verifier, sign(claims(GROUPS))) is AuthFailure.UNKNOWN_KID


def test_jwks_cache_serves_repeated_tokens_from_the_trusted_uri_only() -> None:
    verifier, jwks = make_verifier()
    for _ in range(5):
        verifier.verify(sign(claims(GROUPS)))
    assert jwks.requests == [TEST_CONFIG.jwks_uri]
    assert TEST_CONFIG.jwks_uri == f"{TEST_ISSUER}/.well-known/jwks.json"


# --- outages ----------------------------------------------------------------------


def test_outage_with_cached_key_keeps_verifying() -> None:
    verifier, jwks = make_verifier()
    verifier.verify(sign(claims(GROUPS)))
    jwks.available = False
    assert verifier.verify(sign(claims(GROUPS))).groups == tuple(GROUPS)
    assert len(jwks.requests) == 1


def test_outage_without_cached_key_is_unavailable() -> None:
    verifier, jwks = make_verifier()
    jwks.available = False
    with pytest.raises(AuthenticationUnavailableError) as info:
        verifier.verify(sign(claims(GROUPS)))
    assert info.value.reason == "jwks_unavailable"


def test_failed_fetches_back_off_instead_of_retrying_per_request() -> None:
    clock = FakeClock()
    verifier, jwks = make_verifier(clock=clock)
    jwks.available = False
    for _ in range(20):
        with pytest.raises(AuthenticationUnavailableError):
            verifier.verify(sign(claims(GROUPS)))
    assert len(jwks.requests) == 1
    clock.now += 31
    jwks.available = True
    assert verifier.verify(sign(claims(GROUPS)))
    assert len(jwks.requests) == 2


@pytest.mark.parametrize(
    "response",
    [[], {"keys": []}, {"keys": [{"kty": "EC", "kid": "x"}]}, {"keys": "nope"}, "text"],
)
def test_unusable_jwks_response_is_unavailable_not_unknown_kid(response: Any) -> None:
    client = oidc.TrustedJwksClient(
        TEST_CONFIG.jwks_uri,
        lifespan=300,
        cooldown_duration=30,
        transport=lambda uri, timeout: response,
    )
    verifier = oidc.OidcVerifier(TEST_CONFIG, client)
    with pytest.raises(AuthenticationUnavailableError):
        verifier.verify(sign(claims(GROUPS)))


def test_cached_keys_survive_an_unusable_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = FakeClock()
    monkeypatch.setattr(time, "monotonic", clock)
    verifier, jwks = make_verifier(clock=clock)
    verifier.verify(sign(claims(GROUPS)))
    jwks.keys = {}
    clock.now += 31
    rogue = sign(claims(GROUPS), key=new_key(), kid="unseen-kid")
    with pytest.raises(AuthenticationUnavailableError):
        verifier.verify(rogue)
    # The good key set was restored, so legitimate tokens still verify.
    assert verifier.verify(sign(claims(GROUPS))).groups == tuple(GROUPS)


# --- AUTHN-12 attacker-controlled key locations -------------------------------------


def test_authn_12_jku_x5u_and_embedded_keys_are_never_followed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("unexpected network access")

    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    monkeypatch.setattr(urllib.request, "build_opener", no_network)
    verifier, jwks = make_verifier()
    attacker = new_key()
    attacker_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(attacker.public_key()))
    hostile_headers: dict[str, Any] = {
        "jku": "https://attacker.example/jwks.json",
        "x5u": "https://attacker.example/cert.pem",
        "jwk": attacker_jwk,
    }
    unknown = sign(claims(GROUPS), key=attacker, kid="attacker-kid", headers=hostile_headers)
    assert reason(verifier, unknown) is AuthFailure.UNKNOWN_KID
    reused = sign(claims(GROUPS), key=attacker, kid=TEST_KID, headers=hostile_headers)
    assert reason(verifier, reused) is AuthFailure.INVALID_SIGNATURE
    assert set(jwks.requests) == {TEST_CONFIG.jwks_uri}


# --- configuration -------------------------------------------------------------------


def test_issuer_must_be_https_and_unconfigured_means_no_verifier() -> None:
    from pydantic import ValidationError

    from app.core.config import Settings

    for bad in ("http://issuer.example/pool", "https://issuer.example/pool?x=1", "ftp://x"):
        with pytest.raises(ValidationError):
            Settings(oidc_issuer=bad)
    assert oidc.build_oidc_verifier(Settings(oidc_issuer="", oidc_client_ids="a")) is None
    assert oidc.build_oidc_verifier(Settings(oidc_issuer=TEST_ISSUER, oidc_client_ids="")) is None
    configured = Settings(oidc_issuer=TEST_ISSUER, oidc_client_ids=" a , b ")
    assert configured.oidc_client_id_values == frozenset({"a", "b"})
    assert oidc.build_oidc_verifier(configured) is not None


# --- production network path (transport=None): PyJWT's own fetch_data -----------


class _Response(io.BytesIO):
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class _ScriptedOpener:
    """Stands in for urllib's opener so PyJWT's real fetch path runs offline."""

    def __init__(self, bodies: list[bytes]) -> None:
        self.bodies = bodies
        self.urls: list[str] = []
        self.handlers: list[str] = []

    def build(self, *handlers: object) -> "_ScriptedOpener":
        self.handlers = [type(h).__name__ for h in handlers]
        return self

    def open(self, request: urllib.request.Request, timeout: float | None = None) -> _Response:
        self.urls.append(request.full_url)
        return _Response(self.bodies.pop(0))


def _production_verifier(
    monkeypatch: pytest.MonkeyPatch, bodies: list[bytes]
) -> tuple[oidc.OidcVerifier, _ScriptedOpener]:
    opener = _ScriptedOpener(bodies)
    monkeypatch.setattr(urllib.request, "build_opener", opener.build)
    return oidc.OidcVerifier.from_config(TEST_CONFIG), opener


GOOD_JWKS = json.dumps({"keys": [public_jwk(SIGNING_KEY, TEST_KID)]}).encode()


def test_production_fetch_path_verifies_and_refuses_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier, opener = _production_verifier(monkeypatch, [GOOD_JWKS])
    assert verifier.verify(sign(claims(GROUPS))).groups == tuple(GROUPS)
    assert opener.urls == [TEST_CONFIG.jwks_uri]
    assert "_NoRedirectHandler" in opener.handlers


@pytest.mark.parametrize("body", [b"not json at all", b"[]", b'{"keys": []}', b"\xff\xfe"])
def test_production_unusable_response_is_unavailable_with_backoff(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    verifier, opener = _production_verifier(monkeypatch, [body])
    for _ in range(5):
        with pytest.raises(AuthenticationUnavailableError):
            verifier.verify(sign(claims(GROUPS)))
    # The failure starts the backoff: one request, not one per token.
    assert len(opener.urls) == 1


def test_production_unusable_refresh_keeps_the_good_key_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    monkeypatch.setattr(time, "monotonic", clock)
    verifier, opener = _production_verifier(monkeypatch, [GOOD_JWKS, b"not json at all"])
    verifier.verify(sign(claims(GROUPS)))
    clock.now += 31
    with pytest.raises(AuthenticationUnavailableError):
        verifier.verify(sign(claims(GROUPS), key=new_key(), kid="unseen-kid"))
    assert verifier.verify(sign(claims(GROUPS))).groups == tuple(GROUPS)
    assert len(opener.urls) == 2


def test_every_emitted_reason_is_a_registered_security_event() -> None:
    from app.core import telemetry

    emitted = {r.value for r in AuthFailure} | {
        "jwks_unavailable",
        "auth_not_configured",
        "identity_mapping_denied",
        "unknown_tenant",
        "unknown_role",
    }
    assert emitted <= telemetry.SECURITY_EVENT_NAMES


def test_pinned_pyjwt_internals_used_by_the_jwks_client_exist() -> None:
    """Tripwire: TrustedJwksClient restores this cache entry on a bad refresh."""
    from jwt.jwk_set_cache import JWKSetCache

    assert jwt.__version__ == "2.15.1"
    assert hasattr(JWKSetCache(300), "jwk_set_with_timestamp")
    assert hasattr(jwt.PyJWKClient, "_as_jwk_set_payload")
