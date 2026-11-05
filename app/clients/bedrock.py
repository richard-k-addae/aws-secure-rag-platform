"""Amazon Bedrock invocation service.

Wraps the Converse API with input validation, size limits, timing,
and redacted structured logging. Model ID comes from configuration.
"""
import time
import uuid
from dataclasses import dataclass
from typing import Any

import boto3

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.telemetry import (
    GEN_AI_OPERATION_DURATION,
    GEN_AI_TOKEN_USAGE,
    TRACER,
    record_error,
)

logger = get_logger(__name__)


class PromptTooLargeError(ValueError):
    """Input exceeds the configured character limit."""


@dataclass(frozen=True)
class InvocationResult:
    request_id: str
    text: str
    model_id: str
    input_tokens: int
    output_tokens: int
    latency_ms: int


class BedrockService:
    def __init__(self, client: Any | None = None) -> None:
        settings = get_settings()
        self._settings = settings
        self._client = client or boto3.client("bedrock-runtime", region_name=settings.aws_region)

    def invoke(self, prompt: str, system: str | None = None) -> InvocationResult:
        settings = self._settings
        start = time.monotonic()
        metric_started = time.perf_counter()
        attributes = {"operation": "chat", "model": settings.bedrock_model_id}
        with TRACER.start_as_current_span("gen_ai.chat") as span:
            span.set_attribute("operation", "chat")
            span.set_attribute("model", settings.bedrock_model_id)
            try:
                if len(prompt) > settings.max_input_chars:
                    raise PromptTooLargeError(
                        f"Input of {len(prompt)} chars exceeds limit of {settings.max_input_chars}"
                    )

                request_id = str(uuid.uuid4())
                kwargs: dict[str, Any] = {
                    "modelId": settings.bedrock_model_id,
                    "messages": [{"role": "user", "content": [{"text": prompt}]}],
                    "inferenceConfig": {"maxTokens": settings.max_output_tokens},
                }
                if system:
                    kwargs["system"] = [{"text": system}]

                response = self._client.converse(**kwargs)
                latency_ms = int((time.monotonic() - start) * 1000)
                usage = response.get("usage", {})
                input_tokens = int(usage.get("inputTokens", 0))
                output_tokens = int(usage.get("outputTokens", 0))
                text = "".join(
                    block.get("text", "")
                    for block in response.get("output", {}).get("message", {}).get("content", [])
                )
                result = InvocationResult(
                    request_id=request_id,
                    text=text,
                    model_id=settings.bedrock_model_id,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    latency_ms=latency_ms,
                )
                span.set_attribute("outcome", "success")
                GEN_AI_TOKEN_USAGE.record(
                    input_tokens,
                    {**attributes, "token.type": "input", "outcome": "success"},
                )
                GEN_AI_TOKEN_USAGE.record(
                    output_tokens,
                    {**attributes, "token.type": "output", "outcome": "success"},
                )

                log = logger.bind(
                    request_id=request_id,
                    model_id=result.model_id,
                    input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens,
                    latency_ms=latency_ms,
                )
                if settings.log_full_content and settings.app_env == "dev":
                    log = log.bind(prompt=prompt, response=text, synthetic_data_mode=True)
                log.info("bedrock_invocation")
                return result
            except Exception as exc:
                error_type = record_error(span, exc)
                span.set_attribute("outcome", "error")
                attributes["error.type"] = error_type
                raise
            finally:
                GEN_AI_OPERATION_DURATION.record(
                    time.perf_counter() - metric_started,
                    {**attributes, "outcome": "error" if "error.type" in attributes else "success"},
                )
