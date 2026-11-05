"""Shared test helpers."""
from unittest.mock import MagicMock

from app.auth.permissions import Classification, Role, allowed_classifications
from app.auth.tenancy import TenantContext
from app.clients.bedrock import BedrockService
from app.tests.identity import bearer, install_test_verifier

# Signed synthetic access tokens from the deterministic test issuer
# (app/tests/identity.py). Tenant and role come from verified groups.
TENANT_A_HEADERS = bearer("tenant-a", "reader")
TENANT_B_HEADERS = bearer("tenant-b", "reader")
ADMIN_A_HEADERS = bearer("tenant-a", "admin")
INGESTOR_A_HEADERS = bearer("tenant-a", "ingestor")
INGESTOR_B_HEADERS = bearer("tenant-b", "ingestor")


def context(tenant_id: str = "tenant-a", role: Role = Role.READER) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        role=role,
        allowed_classifications=allowed_classifications(role),
    )


def make_bedrock(text: str = "grounded answer [1]") -> BedrockService:
    mock = MagicMock()
    mock.converse.return_value = {
        "output": {"message": {"content": [{"text": text}]}},
        "usage": {"inputTokens": 8, "outputTokens": 4},
    }
    return BedrockService(client=mock)


def chunk(source: str = "policy.md", content: str = "Retention is 7 years.") -> object:
    from app.rag.retrieval import RetrievedChunk

    return RetrievedChunk(source=source, chunk_index=0, content=content, score=0.9)


__all__ = [
    "ADMIN_A_HEADERS",
    "INGESTOR_A_HEADERS",
    "INGESTOR_B_HEADERS",
    "TENANT_A_HEADERS",
    "TENANT_B_HEADERS",
    "Classification",
    "chunk",
    "context",
    "install_test_verifier",
    "make_bedrock",
]
