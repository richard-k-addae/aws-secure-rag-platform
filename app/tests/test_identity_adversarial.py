"""Adversarial identity tests at the HTTP boundary (M8: AUTHZ-ID, AUTHN-11, LOG).

Caller-controlled input (headers, query string, body) must not influence the
verified TenantContext, failures must stay generic to the caller, and no token
material may reach logs or telemetry. Real-PostgreSQL proof of the verified
tenant reaching row-level security is in test_rls_integration.py.
"""
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import get_bedrock_service, get_ingestion_service, get_rag_service
from app.auth import oidc
from app.auth.permissions import Role, allowed_classifications
from app.clients.bedrock import BedrockService
from app.core import telemetry
from app.main import app
from app.rag.service import RagService
from app.tests.conftest import (
    ADMIN_A_HEADERS,
    INGESTOR_A_HEADERS,
    TENANT_A_HEADERS,
    make_bedrock,
)
from app.tests.identity import TEST_CONFIG, FakeJwks, bearer, claims, new_key, sign

client = TestClient(app, raise_server_exceptions=False)
FORGED = {"X-Tenant-Id": "tenant-b", "X-Tenant-Role": "admin"}
GENERIC_BODIES = {
    401: {"detail": "Not authenticated"},
    403: {"detail": "Forbidden"},
    503: {"detail": "Authentication unavailable"},
}


def query_with_spy(headers: dict[str, str], url: str = "/v1/query") -> tuple[Any, MagicMock]:
    embeddings = MagicMock()
    embeddings.embed.return_value = [0.1]
    store = MagicMock()
    store.search.return_value = []
    service = RagService(bedrock=make_bedrock(), embeddings=embeddings, store=store)
    app.dependency_overrides[get_rag_service] = lambda: service
    try:
        response = client.post(url, json={"question": "What is the policy?"}, headers=headers)
    finally:
        app.dependency_overrides.pop(get_rag_service)
    return response, store


def bedrock_with_model() -> tuple[BedrockService, MagicMock]:
    model = MagicMock()
    model.converse.return_value = {
        "output": {"message": {"content": [{"text": "SYNTHETIC"}]}},
        "usage": {"inputTokens": 1, "outputTokens": 1},
    }
    return BedrockService(client=model), model


def generate(headers: dict[str, str]) -> tuple[Any, MagicMock]:
    bedrock, model = bedrock_with_model()
    app.dependency_overrides[get_bedrock_service] = lambda: bedrock
    try:
        response = client.post("/v1/generate", json={"prompt": "p"}, headers=headers)
    finally:
        app.dependency_overrides.pop(get_bedrock_service)
    return response, model


def ingest(headers: dict[str, str], classification: str = "internal") -> tuple[Any, MagicMock]:
    service = MagicMock()
    service.ingest_file.return_value = 1
    app.dependency_overrides[get_ingestion_service] = lambda: service
    try:
        response = client.post(
            "/v1/documents/ingest",
            json={"source": "employee_security_policy.md", "classification": classification},
            headers=headers,
        )
    finally:
        app.dependency_overrides.pop(get_ingestion_service)
    return response, service


# --- header authority is gone -------------------------------------------------------


def test_identity_headers_are_not_part_of_the_api_contract() -> None:
    schema = app.openapi()
    names = {
        p["name"].lower()
        for path in schema["paths"].values()
        for operation in path.values()
        for p in operation.get("parameters", [])
    }
    assert not {"x-tenant-id", "x-tenant-role"} & names
    schemes = schema["components"]["securitySchemes"]
    assert any(s.get("type") == "http" and s.get("scheme") == "bearer" for s in schemes.values())
    for path in ("/v1/query", "/v1/generate", "/v1/documents/ingest"):
        assert schema["paths"][path]["post"].get("security"), path
    assert not schema["paths"]["/healthz"]["get"].get("security")


def test_authz_id_01_tenant_header_cannot_change_verified_tenant() -> None:
    response, store = query_with_spy({**TENANT_A_HEADERS, **FORGED})
    assert response.status_code == 200
    context = store.search.call_args.kwargs["context"]
    assert (context.tenant_id, context.role) == ("tenant-a", Role.READER)


def test_authz_id_02_role_header_cannot_unlock_generate() -> None:
    response, model = generate({**TENANT_A_HEADERS, **FORGED})
    assert response.status_code == 403
    model.converse.assert_not_called()


def test_headers_alone_authenticate_nothing() -> None:
    for path in ("/v1/query", "/v1/generate", "/v1/documents/ingest"):
        response = client.post(path, json={}, headers=FORGED)
        assert response.status_code == 401, path
        assert response.json() == GENERIC_BODIES[401]


def test_authz_id_03_tenant_a_token_writes_and_authorizes_only_as_tenant_a() -> None:
    response, service = ingest({**INGESTOR_A_HEADERS, **FORGED})
    assert response.status_code == 200
    kwargs = service.ingest_file.call_args.kwargs
    assert kwargs["tenant_id"] == "tenant-a"
    assert (kwargs["authorize_as"].tenant_id, kwargs["authorize_as"].role) == (
        "tenant-a",
        Role.INGESTOR,
    )


@pytest.mark.parametrize(
    "attempt",
    [
        {"url": "/v1/generate?role=admin&tenant_id=tenant-b"},
        {"headers": {"X-Tenant-Role": "admin", "X-Role": "admin", "X-User-Role": "admin"}},
        {"headers": {"X-Forwarded-User": "admin", "X-Amzn-Oidc-Data": "forged"}},
    ],
)
def test_authz_id_04_role_cannot_be_elevated_by_request_manipulation(
    attempt: dict[str, Any],
) -> None:
    bedrock, model = bedrock_with_model()
    app.dependency_overrides[get_bedrock_service] = lambda: bedrock
    try:
        response = client.post(
            attempt.get("url", "/v1/generate"),
            json={"prompt": "p"},
            headers={**TENANT_A_HEADERS, **attempt.get("headers", {})},
        )
    finally:
        app.dependency_overrides.pop(get_bedrock_service)
    assert response.status_code == 403
    model.converse.assert_not_called()


def test_role_in_request_body_is_rejected() -> None:
    response = client.post(
        "/v1/query",
        json={"question": "q", "role": "admin", "tenant_id": "tenant-b"},
        headers=TENANT_A_HEADERS,
    )
    assert response.status_code == 422


def test_authz_id_05_verified_identity_reaches_classification_and_acl_checks() -> None:
    _, store = query_with_spy(TENANT_A_HEADERS)
    assert store.search.call_args.kwargs["context"].allowed_classifications == (
        allowed_classifications(Role.READER)
    )
    denied, _ = ingest(INGESTOR_A_HEADERS, classification="restricted")
    assert denied.status_code == 403
    allowed, service = ingest(ADMIN_A_HEADERS, classification="restricted")
    assert allowed.status_code == 200
    assert service.ingest_file.call_args.kwargs["authorize_as"].role is Role.ADMIN


# --- AUTHN-11 and the error contract --------------------------------------------------


@pytest.mark.parametrize(
    "authorization",
    [None, "", "Bearer", "Bearer ", "Basic dXNlcjpwYXNz", "Token abc", "bearer"],
)
def test_authn_11_missing_or_non_bearer_authorization_is_401(authorization: str | None) -> None:
    headers = {} if authorization is None else {"Authorization": authorization}
    response, store = query_with_spy(headers)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json() == GENERIC_BODIES[401]
    store.search.assert_not_called()


def test_every_authentication_failure_has_the_same_generic_body() -> None:
    now = claims(["tenant:tenant-a", "role:reader"])
    failures = {
        "expired": sign({**now, "iat": now["iat"] - 7200, "exp": now["iat"] - 3600}),
        "forged": sign(now, key=new_key()),
        "unknown_kid": sign(now, key=new_key(), kid="never-published"),
        "wrong_issuer": sign({**now, "iss": "https://evil.example"}),
        "id_token": sign({**now, "token_use": "id"}),
        "malformed": "not.a.jwt",
    }
    for name, token in failures.items():
        response = client.post(
            "/v1/query", json={"question": "q"}, headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401, name
        assert response.json() == GENERIC_BODIES[401], name
        for part in token.split("."):
            if len(part) > 8:
                assert part not in response.text, name


def test_identity_mapping_denial_is_a_generic_403() -> None:
    for headers in (
        bearer("tenant-z", "reader"),
        {"Authorization": f"Bearer {sign(claims(['tenant:tenant-a']))}"},
    ):
        response = client.post("/v1/query", json={"question": "q"}, headers=headers)
        assert response.status_code == 403
        assert response.json() == GENERIC_BODIES[403]
        assert "tenant-z" not in response.text


def test_unavailable_or_unconfigured_verification_is_a_generic_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    down = FakeJwks({})
    down.available = False
    monkeypatch.setattr(
        oidc, "get_oidc_verifier", lambda: oidc.OidcVerifier.from_config(TEST_CONFIG, down)
    )
    response = client.post("/v1/query", json={"question": "q"}, headers=TENANT_A_HEADERS)
    assert response.status_code == 503
    assert response.json() == GENERIC_BODIES[503]
    monkeypatch.setattr(oidc, "get_oidc_verifier", lambda: None)
    response = client.post("/v1/query", json={"question": "q"}, headers=TENANT_A_HEADERS)
    assert response.status_code == 503
    assert response.json() == GENERIC_BODIES[503]


# --- LOG-01 / LOG-02 -------------------------------------------------------------------


def test_log_01_and_02_tokens_never_logged_and_reasons_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    events: list[dict[str, str]] = []
    monkeypatch.setattr(telemetry.SECURITY_EVENTS, "add", lambda value, attrs: events.append(attrs))
    valid = TENANT_A_HEADERS["Authorization"].removeprefix("Bearer ")
    forged = sign(claims(["tenant:tenant-a", "role:admin"]), key=new_key())
    unmapped = sign(claims(["tenant:tenant-q", "role:reader"]))
    caplog.set_level("DEBUG")
    for token in (valid, forged, unmapped):
        query_with_spy({"Authorization": f"Bearer {token}"})
    query_with_spy({})
    output = caplog.text + "".join(capsys.readouterr())
    # Control: the rejections really were logged, with bounded reasons only.
    assert "authentication_rejected" in output
    assert "invalid_signature" in output and "missing_token" in output
    assert "identity_mapping_denied" in output
    for token in (valid, forged, unmapped):
        assert token not in output
        assert token.rsplit(".", 1)[1] not in output
    assert "Authorization" not in output and "Bearer " not in output
    assert "tenant-q" not in output
    for attrs in events:
        assert set(attrs) <= {"event", "role", "classification"}
        assert attrs["event"] in telemetry.SECURITY_EVENT_NAMES
    assert {"event": "invalid_signature"} in events
    assert {"event": "unknown_tenant"} in events
    assert {"event": "missing_token"} in events
