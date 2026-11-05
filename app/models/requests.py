from pydantic import BaseModel, ConfigDict, Field

from app.auth.permissions import Classification, Role
from app.core.config import MAX_QUESTION_CHARS


class QueryRequest(BaseModel):
    """A user question answered from the controlled knowledge base.

    Tenant identity is deliberately absent: it is resolved server-side and
    can never be asserted by the caller. Unknown fields are rejected so a
    smuggled `tenant_id` fails loudly instead of being silently ignored.
    """

    model_config = ConfigDict(extra="forbid")

    # Same constant the runtime limit is bounded by, so the published contract
    # and the enforced limit cannot drift apart.
    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)
    top_k: int | None = Field(default=None, ge=1, le=20)


class GenerateRequest(BaseModel):
    """Direct model invocation. Admin-only: it bypasses retrieval entirely."""

    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(min_length=1, max_length=8000)


class IngestRequest(BaseModel):
    """Ingest a document from the synthetic corpus into the caller's tenant."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=512)
    classification: Classification
    document_id: str | None = Field(default=None, max_length=512)
    # Optional per-document ACL. Empty means classification alone governs access.
    allowed_roles: list[Role] = Field(default_factory=list)
