"""Bedrock embedding client.

Uses the configured embedding model (Titan Text Embeddings v2 by default).
The client is injectable for testing; no network calls in unit tests.
"""
import json
import time
from typing import Any

import boto3

from app.core.config import get_settings
from app.core.telemetry import GEN_AI_OPERATION_DURATION, TRACER, record_error


class EmbeddingService:
    def __init__(self, client: Any | None = None) -> None:
        settings = get_settings()
        self._settings = settings
        self._client = client or boto3.client("bedrock-runtime", region_name=settings.aws_region)

    def embed(self, text: str) -> list[float]:
        started = time.perf_counter()
        attributes = {
            "operation": "embeddings",
            "model": self._settings.embedding_model_id,
        }
        with TRACER.start_as_current_span("gen_ai.embeddings") as span:
            span.set_attribute("operation", "embeddings")
            span.set_attribute("model", self._settings.embedding_model_id)
            try:
                body = json.dumps(
                    {"inputText": text, "dimensions": self._settings.embedding_dimensions}
                )
                response = self._client.invoke_model(
                    modelId=self._settings.embedding_model_id,
                    body=body,
                    contentType="application/json",
                    accept="application/json",
                )
                payload = json.loads(response["body"].read())
                embedding: list[float] = payload["embedding"]
                outcome = "success"
                span.set_attribute("outcome", outcome)
                return embedding
            except Exception as exc:
                error_type = record_error(span, exc)
                span.set_attribute("outcome", "error")
                attributes["error.type"] = error_type
                raise
            finally:
                GEN_AI_OPERATION_DURATION.record(
                    time.perf_counter() - started,
                    {**attributes, "outcome": "error" if "error.type" in attributes else "success"},
                )

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]
