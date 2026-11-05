"""Application settings.

Model IDs are configuration, not code: the service works with any Bedrock
text model that supports the Converse API and any Bedrock embedding model,
demonstrating model portability.
"""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# The published /v1/query question limit. QueryRequest uses this constant as
# its schema max_length, so the API contract and the runtime check share one
# number. Settings may tighten the runtime limit but never loosen it past it.
MAX_QUESTION_CHARS = 4000


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "dev"
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "anthropic.claude-sonnet-example-model-id"
    embedding_model_id: str = "amazon.titan-embed-text-v2:0"
    embedding_dimensions: int = 1024
    log_level: str = "INFO"
    # Full prompt/response logging is only permitted in dev with synthetic data.
    log_full_content: bool = False
    # Size of the whole user message sent to the model (framing, question and
    # retrieved passages; the fixed system prompt is not counted). Retrieved
    # passages are fitted into whatever the question and framing leave over.
    max_input_chars: int = 8000
    # Limit on the caller's own question for /v1/query, enforced twice: by the
    # QueryRequest schema (422) and, for direct service callers, by RagService
    # before any retrieval (QuestionTooLargeError -> 413 + prompt_too_large).
    # Chosen so a maximal question still leaves room for at least one
    # worst-case passage; test_prompt_budget.py asserts that guarantee.
    max_question_chars: int = Field(default=MAX_QUESTION_CHARS, ge=1, le=MAX_QUESTION_CHARS)
    max_output_tokens: int = 1024

    # Vector store (local dev defaults; production values come from Secrets Manager)
    # Runtime role: NOSUPERUSER NOBYPASSRLS so row-level security applies to it.
    database_url: str = "postgresql://rag_app:rag_app@localhost:5432/rag"
    # Administrative role: DDL, policy and role provisioning only. Never used at runtime.
    admin_database_url: str = "postgresql://rag:rag@localhost:5432/rag"
    app_db_role: str = "rag_app"
    # Dev-only default; overridden from Secrets Manager in AWS.
    app_db_password: str = "rag_app"  # noqa: S105 - local development placeholder
    retrieval_top_k: int = 5
    retrieval_min_score: float = 0.35

    # Chunking
    chunk_max_chars: int = 1200
    chunk_overlap_chars: int = 150

    # Tenancy (dev resolver only; replaced by verified Cognito claims in M4)
    tenant_allowlist: str = "tenant-a,tenant-b"
    default_tenant_role: str = "reader"

    @property
    def tenant_allowlist_values(self) -> frozenset[str]:
        return frozenset(t.strip() for t in self.tenant_allowlist.split(",") if t.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
