from typing import Annotated

import psycopg
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import get_bedrock_service, get_rag_service
from app.auth.permissions import Action
from app.auth.tenancy import TenantContext, require
from app.clients.bedrock import BedrockService, PromptTooLargeError
from app.core.security import sanitize_text
from app.core.telemetry import record_security_event
from app.models.requests import GenerateRequest, QueryRequest
from app.models.responses import GenerateResponse, QueryResponse
from app.rag.prompting import QuestionTooLargeError
from app.rag.service import RagService

router = APIRouter(tags=["query"])

THROTTLE_CODES = {
    "ThrottlingException",
    "TooManyRequestsException",
    "ServiceQuotaExceededException",
}


@router.post("/query", response_model=QueryResponse)
def query(
    body: QueryRequest,
    service: Annotated[RagService, Depends(get_rag_service)],
    context: Annotated[TenantContext, require(Action.QUERY)],
) -> QueryResponse:
    question = sanitize_text(body.question)
    try:
        return service.query(question, context=context, top_k=body.top_k)
    except QuestionTooLargeError as exc:
        # Only the caller's own question is attributed to the caller. Retrieved
        # context is fitted to the budget by the service; a generic
        # PromptTooLargeError here would be an internal invariant violation
        # and is deliberately left to the generic 500 handler.
        record_security_event("prompt_too_large", role=context.role.value)
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except psycopg.OperationalError as exc:
        # Fail closed: no retrieval means no answer - never fall back to model memory.
        raise HTTPException(
            status_code=503,
            detail="Retrieval store unavailable; request refused (fail-closed).",
        ) from exc
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in THROTTLE_CODES:
            raise HTTPException(
                status_code=503,
                detail="Model provider throttled the request; retry with backoff.",
                headers={"Retry-After": "5"},
            ) from exc
        raise


@router.post("/generate", response_model=GenerateResponse)
def generate(
    body: GenerateRequest,
    service: Annotated[BedrockService, Depends(get_bedrock_service)],
    context: Annotated[TenantContext, require(Action.GENERATE)],
) -> GenerateResponse:
    try:
        result = service.invoke(sanitize_text(body.prompt))
    except PromptTooLargeError as exc:
        record_security_event("prompt_too_large", role=context.role.value)
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    return GenerateResponse(**result.__dict__)
