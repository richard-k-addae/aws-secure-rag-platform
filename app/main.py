"""FastAPI application entrypoint.

Phase 1-2: health, generate, and RAG query endpoints.
Phase 4 adds Cognito JWT middleware, rate limiting, and document-level
authorization (see app/auth/).
"""
from fastapi import FastAPI

from app.api.routes import documents, health, query
from app.core.logging import configure_logging
from app.core.telemetry import configure_telemetry

configure_logging()

app = FastAPI(
    title="AWS Secure RAG Platform",
    description="Security-first RAG service on Amazon Bedrock",
    version="0.2.0",
)

app.include_router(health.router)
app.include_router(query.router, prefix="/v1")
app.include_router(documents.router, prefix="/v1")

# A no-op unless an OTLP endpoint is configured in the environment.
configure_telemetry(app)
