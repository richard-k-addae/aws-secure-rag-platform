"""Verified OIDC identity: Cognito user pool access tokens (M8, closes ID-01).

Authentication happens before any authorization decision:

    Authorization: Bearer <access token>
        -> structure, header and algorithm checks (no network)
        -> signing key from the issuer's JWKS (trusted URI only)
        -> RS256 signature, iss, exp/nbf/iat, token_use, client_id (PyJWT)
        -> VerifiedPrincipal

Trust anchors come only from server configuration: the issuer is configured,
the JWKS URI is derived from it, the algorithm list is fixed. Nothing in the
token (alg, jku, x5u, kid URLs, iss) can redirect key lookup. Decoding is never
treated as verification.

Failures carry a bounded reason for logs and metrics; callers only ever see a
generic message. The raw token is never stored, logged or returned.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from typing import Any

import jwt
from jwt import PyJWK, PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from app.core.config import Settings, get_settings

ALGORITHM = "RS256"
REQUIRED_CLAIMS = ("exp", "iat", "iss", "sub", "token_use", "client_id")
MAX_TOKEN_CHARS = 8192
MAX_KID_CHARS = 256
JWKS_TIMEOUT_SECONDS = 5.0


class AuthFailure(StrEnum):
    """Bounded reasons; the only failure detail that leaves the verifier."""

    MISSING_TOKEN = "missing_token"  # noqa: S105 - reason name, not a secret
    MALFORMED_TOKEN = "malformed_token"  # noqa: S105 - reason name, not a secret
    INVALID_ALGORITHM = "invalid_algorithm"
    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED_TOKEN = "expired_token"  # noqa: S105 - reason name, not a secret
    TOKEN_NOT_YET_VALID = "token_not_yet_valid"  # noqa: S105 - reason name, not a secret
    WRONG_ISSUER = "wrong_issuer"
    WRONG_AUDIENCE = "wrong_audience"
    WRONG_CLIENT = "wrong_client"
    WRONG_TOKEN_USE = "wrong_token_use"  # noqa: S105 - reason name, not a secret
    MISSING_CLAIM = "missing_claim"
    UNKNOWN_KID = "unknown_kid"
    INVALID_TOKEN = "invalid_token"  # noqa: S105 - reason name, not a secret


class AuthenticationError(Exception):
    """Authentication failed (HTTP 401). ``reason`` is bounded; no token data."""

    def __init__(self, reason: AuthFailure) -> None:
        super().__init__(reason.value)
        self.reason = reason


class AuthenticationUnavailableError(Exception):
    """Verification could not be completed by the server (HTTP 503)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class VerifiedPrincipal:
    """Identity material taken only from a verified access token.

    Holds no raw token. ``sub`` and ``client_id`` are excluded from repr so a
    stray log of the object cannot carry identifiers either.
    """

    sub: str
    client_id: str
    # None: the cognito:groups claim was present but not a list of strings.
    groups: tuple[str, ...] | None

    def __repr__(self) -> str:
        count = "malformed" if self.groups is None else len(self.groups)
        return f"VerifiedPrincipal(groups={count})"


@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    client_ids: frozenset[str]
    audience: str | None
    leeway_seconds: int
    jwks_cache_ttl_seconds: int
    jwks_refresh_cooldown_seconds: int

    @property
    def jwks_uri(self) -> str:
        # Derived from the trusted issuer, never read from a token (Cognito layout).
        return f"{self.issuer.rstrip('/')}/.well-known/jwks.json"

    @classmethod
    def from_settings(cls, settings: Settings) -> "OidcConfig | None":
        if not settings.oidc_issuer or not settings.oidc_client_id_values:
            return None
        return cls(
            issuer=settings.oidc_issuer,
            client_ids=settings.oidc_client_id_values,
            audience=settings.oidc_audience or None,
            leeway_seconds=settings.oidc_leeway_seconds,
            jwks_cache_ttl_seconds=settings.oidc_jwks_cache_ttl_seconds,
            jwks_refresh_cooldown_seconds=settings.oidc_jwks_refresh_cooldown_seconds,
        )


JwksTransport = Callable[[str, float], Any]


class TrustedJwksClient(PyJWKClient):
    """PyJWKClient for one trusted URI, with a failure backoff.

    PyJWT caches the key set, refuses redirects and limits unknown-``kid``
    refreshes to one per cooldown after a successful fetch. A failed fetch does
    not start that cooldown, so during an endpoint outage every unknown-kid or
    cache-expired request would retry the network. This subclass answers
    "unavailable" without a request until the cooldown has passed since the
    last failure.

    ``transport`` exists for deterministic tests (an in-process JWKS). When it
    is None, PyJWT's own fetch (TLS, no redirects, timeout) is used unchanged.
    """

    def __init__(
        self,
        uri: str,
        *,
        lifespan: float,
        cooldown_duration: float,
        timeout: float = JWKS_TIMEOUT_SECONDS,
        transport: JwksTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(
            uri,
            cache_jwk_set=True,
            lifespan=lifespan,
            cooldown_duration=cooldown_duration,
            timeout=timeout,
        )
        self._transport = transport
        self._clock = clock
        self._failure_backoff = cooldown_duration
        self._failed_at: float | None = None

    def fetch_data(self) -> Any:
        """Fetch and validate the key set; any unusable response is "unavailable".

        PyJWT reports a missing kid and an unusable endpoint response with the
        same exception type, and its network path caches a response before
        the keys are checked. Validating here keeps the two apart (401 vs 503)
        and restores the last good key set if a bad response displaced it.
        """
        now = self._clock()
        if self._failed_at is not None and now - self._failed_at < self._failure_backoff:
            raise PyJWKClientConnectionError("JWKS endpoint recently unavailable")
        cache = self.jwk_set_cache
        previous = cache.jwk_set_with_timestamp if cache is not None else None
        try:
            if self._transport is None:
                data = super().fetch_data()
            else:
                data = self._fetch_with_transport()
            self._require_signing_keys(data)
        except (jwt.PyJWTError, ValueError) as exc:
            # ValueError covers a non-JSON body: PyJWT's fetch_data only wraps
            # network errors, so json.load failures would otherwise escape as a
            # 500 and bypass the failure backoff.
            if cache is not None:
                cache.jwk_set_with_timestamp = previous
            self._failed_at = now
            if isinstance(exc, PyJWKClientConnectionError):
                raise
            raise PyJWKClientConnectionError("JWKS response unusable") from exc
        self._failed_at = None
        return data

    def _fetch_with_transport(self) -> Any:
        assert self._transport is not None
        try:
            data = self._transport(self.uri, self.timeout)
        except OSError as exc:
            raise PyJWKClientConnectionError("Fail to fetch data from the url") from exc
        data = self._as_jwk_set_payload(data)
        self._require_signing_keys(data)
        # Mirrors PyJWKClient.fetch_data: cache and start the refresh cooldown.
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(data)
        self._last_successful_fetch = time.monotonic()
        return data

    @staticmethod
    def _require_signing_keys(data: Any) -> None:
        keys = data.get("keys") if isinstance(data, dict) else None
        usable = isinstance(keys, list) and any(
            isinstance(k, dict)
            and k.get("kty") == "RSA"
            and isinstance(k.get("kid"), str)
            and k.get("use") in ("sig", None)
            for k in keys
        )
        if not usable:
            raise PyJWKClientError("JWKS response contains no RSA signing key")


class OidcVerifier:
    """Verifies Cognito access tokens against one trusted issuer."""

    def __init__(self, config: OidcConfig, jwks: PyJWKClient) -> None:
        self._config = config
        self._jwks = jwks

    @classmethod
    def from_config(
        cls, config: OidcConfig, transport: JwksTransport | None = None
    ) -> "OidcVerifier":
        jwks = TrustedJwksClient(
            config.jwks_uri,
            lifespan=config.jwks_cache_ttl_seconds,
            cooldown_duration=config.jwks_refresh_cooldown_seconds,
            transport=transport,
        )
        return cls(config, jwks)

    def verify(self, token: str) -> VerifiedPrincipal:
        kid = self._checked_kid(token)
        key = self._signing_key(kid)
        claims = self._decode(token, key)
        return self._principal(claims)

    # -- steps ---------------------------------------------------------------

    @staticmethod
    def _checked_kid(token: str) -> str:
        """Structure and header checks; no network and no trust in the payload."""
        if not token or len(token) > MAX_TOKEN_CHARS:
            raise AuthenticationError(AuthFailure.MALFORMED_TOKEN)
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise AuthenticationError(AuthFailure.MALFORMED_TOKEN)
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise AuthenticationError(AuthFailure.MALFORMED_TOKEN) from exc
        if header.get("alg") != ALGORITHM:
            raise AuthenticationError(AuthFailure.INVALID_ALGORITHM)
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > MAX_KID_CHARS:
            raise AuthenticationError(AuthFailure.MALFORMED_TOKEN)
        # jku, x5u, x5c and jwk header parameters are deliberately never read.
        return kid

    def _signing_key(self, kid: str) -> PyJWK:
        try:
            return self._jwks.get_signing_key(kid)
        except PyJWKClientConnectionError as exc:
            raise AuthenticationUnavailableError("jwks_unavailable") from exc
        except PyJWKClientError as exc:
            raise AuthenticationError(AuthFailure.UNKNOWN_KID) from exc
        except jwt.PyJWTError as exc:
            # A key set that cannot be parsed is a server-side fault.
            raise AuthenticationUnavailableError("jwks_unavailable") from exc

    def _decode(self, token: str, key: PyJWK) -> dict[str, Any]:
        config = self._config
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=[ALGORITHM],
                issuer=config.issuer,
                audience=config.audience,
                leeway=config.leeway_seconds,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    # Cognito access tokens carry client_id and no aud unless a
                    # resource binding was requested; aud is checked only then.
                    "verify_aud": config.audience is not None,
                    "require": list(REQUIRED_CLAIMS),
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError(AuthFailure.EXPIRED_TOKEN) from exc
        except jwt.ImmatureSignatureError as exc:
            raise AuthenticationError(AuthFailure.TOKEN_NOT_YET_VALID) from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthenticationError(AuthFailure.WRONG_ISSUER) from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthenticationError(AuthFailure.WRONG_AUDIENCE) from exc
        except jwt.MissingRequiredClaimError as exc:
            raise AuthenticationError(AuthFailure.MISSING_CLAIM) from exc
        except jwt.InvalidAlgorithmError as exc:
            raise AuthenticationError(AuthFailure.INVALID_ALGORITHM) from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthenticationError(AuthFailure.INVALID_SIGNATURE) from exc
        except jwt.DecodeError as exc:
            raise AuthenticationError(AuthFailure.MALFORMED_TOKEN) from exc
        except jwt.InvalidTokenError as exc:
            raise AuthenticationError(AuthFailure.INVALID_TOKEN) from exc
        return claims

    def _principal(self, claims: dict[str, Any]) -> VerifiedPrincipal:
        if claims.get("token_use") != "access":
            raise AuthenticationError(AuthFailure.WRONG_TOKEN_USE)
        client_id = claims.get("client_id")
        if not isinstance(client_id, str) or client_id not in self._config.client_ids:
            raise AuthenticationError(AuthFailure.WRONG_CLIENT)
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise AuthenticationError(AuthFailure.MISSING_CLAIM)
        raw_groups = claims.get("cognito:groups", [])
        # Shape problems are left to the identity mapping, which denies them.
        groups: tuple[str, ...] | None = None
        if isinstance(raw_groups, list) and all(isinstance(g, str) for g in raw_groups):
            groups = tuple(raw_groups)
        return VerifiedPrincipal(sub=sub, client_id=client_id, groups=groups)


def build_oidc_verifier(settings: Settings) -> OidcVerifier | None:
    """Production verifier from trusted settings; None when not configured."""
    config = OidcConfig.from_settings(settings)
    return OidcVerifier.from_config(config) if config else None


@lru_cache
def get_oidc_verifier() -> OidcVerifier | None:
    """The process-wide verifier (one JWKS cache). None means not configured."""
    return build_oidc_verifier(get_settings())
