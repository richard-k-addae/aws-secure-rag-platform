"""FastAPI application entrypoint.

Phase 1-2: health, generate, and RAG query endpoints.
Phase 4 adds Cognito JWT middleware, rate limiting, and document-level
authorization (see app/auth/).
"""
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app.api.routes import documents, health, query
from app.core.logging import configure_logging, get_logger
from app.core.telemetry import configure_telemetry, safe_error_type

configure_logging()
logger = get_logger(__name__)

app = FastAPI(
    title="AWS Secure RAG Platform",
    description="Security-first RAG service on Amazon Bedrock",
    version="0.2.0",
)


async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Return a generic error without logging provider or database details."""
    logger.error("unexpected_application_error", error_type=safe_error_type(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


app.add_exception_handler(Exception, handle_unexpected_error)


@app.middleware("http")
async def sanitize_unexpected_errors(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Stop unexpected exceptions before the server traceback middleware sees them."""
    try:
        response = await call_next(request)
        return response
    except Exception as exc:
        return await handle_unexpected_error(request, exc)

app.include_router(health.router)
app.include_router(query.router, prefix="/v1")
app.include_router(documents.router, prefix="/v1")

# A no-op unless an OTLP endpoint is configured in the environment.
configure_telemetry(app)
