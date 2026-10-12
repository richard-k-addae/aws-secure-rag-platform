"""Generate safe local synthetic traffic for local observability stack validation.

Exercises all instrumentation paths (HTTP routes, RAG queries, Bedrock invocation,
embedding generation, vector retrieval, document ingestion, and security events)
without requiring real AWS Bedrock credentials or exposing sensitive data.
"""

import json
import os
import urllib.error
import urllib.request
from unittest.mock import MagicMock

from botocore.exceptions import ClientError
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from app.auth.permissions import Classification, Role
from app.auth.tenancy import TenantContext
from app.clients.bedrock import BedrockService
from app.core import telemetry
from app.core.config import get_settings
from app.core.security import sanitize_text
from app.rag.embeddings import EmbeddingService
from app.rag.ingestion import IngestionService
from app.rag.retrieval import VectorStore
from app.rag.service import RagService


def send_http(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: dict[str, object] | None = None,
) -> tuple[int, str]:
    headers = headers or {}
    req = urllib.request.Request(url, method=method)  # noqa: S310
    for k, v in headers.items():
        req.add_header(k, v)
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        req.add_header("Content-Type", "application/json")
        req.data = body

    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8")
    except Exception as exc:
        return 0, str(exc)


def main() -> None:
    api_url = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")
    otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    db_url = os.environ.get("DATABASE_URL", "postgresql://rag_app:rag_app@127.0.0.1:5432/rag")

    print(f"Generating synthetic traffic against API: {api_url}, OTLP: {otlp_endpoint}")

    # 1. Send HTTP traffic to local API container
    print("1. Sending HTTP traffic to API...")
    send_http(f"{api_url}/healthz")

    # Security rejections through API
    send_http(f"{api_url}/v1/query", method="POST", data={"question": "hello"})
    # 401 missing_tenant
    send_http(
        f"{api_url}/v1/query",
        method="POST",
        headers={"X-Tenant-Id": "unknown"},
        data={"question": "hello"},
    )
    # 403 unknown_tenant
    send_http(
        f"{api_url}/v1/query",
        method="POST",
        headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "unknown"},
        data={"question": "hello"},
    )
    # 403 unknown_role
    send_http(
        f"{api_url}/v1/generate",
        method="POST",
        headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "reader"},
        data={"prompt": "hello"},
    )
    # 403 action_denied
    send_http(
        f"{api_url}/v1/documents/ingest",
        method="POST",
        headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "ingestor"},
        data={"source": "threat.md", "classification": "restricted"},
    )
    # 403 classification_denied
    send_http(
        f"{api_url}/v1/documents/ingest",
        method="POST",
        headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "admin"},
        data={"source": "../../escape.md", "classification": "internal"},
    )
    # 400 path_rejected

    # 2. Configure local telemetry exporter to send RAG/GenAI metrics & spans to collector
    print("2. Emitting RAG, GenAI, Retrieval, and Ingestion telemetry to OTLP collector...")
    settings = get_settings()
    resource = telemetry.build_resource(settings, "local-synthetic")
    span_exporter = telemetry.ScrubbingSpanExporter(
        OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces")
    )
    metric_exporter = OTLPMetricExporter(endpoint=f"{otlp_endpoint}/v1/metrics")
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    metric_reader = PeriodicExportingMetricReader(metric_exporter)
    meter_provider = MeterProvider(
        resource=resource,
        metric_readers=[metric_reader],
        views=telemetry.METRIC_VIEWS,
    )

    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(meter_provider)

    # 3. Embedding operations
    mock_boto_embed = MagicMock()
    mock_boto_embed.invoke_model.return_value = {
        "body": MagicMock(read=lambda: json.dumps({"embedding": [0.05] * 1024}))
    }
    embed_service = EmbeddingService(client=mock_boto_embed)
    embed_service.embed("synthetic document content")

    mock_boto_embed_err = MagicMock()
    mock_boto_embed_err.invoke_model.side_effect = ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
        "InvokeModel",
    )
    embed_service_err = EmbeddingService(client=mock_boto_embed_err)
    try:
        embed_service_err.embed("failed document content")
    except ClientError:
        pass

    # 4. Bedrock chat generation operations
    mock_boto_bedrock = MagicMock()
    mock_boto_bedrock.converse.return_value = {
        "output": {"message": {"content": [{"text": "Synthetic grounded answer [1]."}]}},
        "usage": {"inputTokens": 45, "outputTokens": 20},
    }
    bedrock_service = BedrockService(client=mock_boto_bedrock)
    bedrock_service.invoke("synthetic prompt")

    mock_boto_bedrock_err = MagicMock()
    mock_boto_bedrock_err.converse.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "Model not available"}},
        "Converse",
    )
    bedrock_service_err = BedrockService(client=mock_boto_bedrock_err)
    try:
        bedrock_service_err.invoke("failing prompt")
    except ClientError:
        pass

    # 5. Vector retrieval & upsert against local PostgreSQL
    store = VectorStore(conninfo=db_url)
    vector = [0.05] * 1024
    store.upsert_chunks(
        tenant_id="tenant-a",
        source="security-policy.md",
        classification=Classification.INTERNAL,
        chunks=[(0, "All systems must maintain strict telemetry scrubbing.", vector)],
        document_id="doc-synth-001",
    )

    ctx_reader = TenantContext("tenant-a", Role.READER, frozenset({Classification.INTERNAL}))
    results = store.search(vector, context=ctx_reader, top_k=3)
    print(f"Retrieved {len(results)} chunks from local vector store.")

    ctx_empty = TenantContext("tenant-b", Role.READER, frozenset({Classification.PUBLIC}))
    results_empty = store.search(vector, context=ctx_empty, top_k=3)
    print(f"Empty search returned {len(results_empty)} chunks.")

    # 6. Ingestion service
    ingestion_service = IngestionService(embeddings=embed_service, store=store)
    ingested_chunks = ingestion_service.ingest_text(
        tenant_id="tenant-a",
        source="compliance-guide.md",
        classification=Classification.PUBLIC,
        text="Telemetry must never log sensitive customer content or prompts.",
        document_id="doc-synth-002",
    )
    print(f"Ingested {ingested_chunks} chunks.")

    # 7. RAG service queries
    rag_service = RagService(bedrock=bedrock_service, embeddings=embed_service, store=store)
    resp_answered = rag_service.query("What is the telemetry policy?", context=ctx_reader)
    print(f"RAG answered query: {resp_answered.answer[:40]}...")

    resp_no_context = rag_service.query("What is the weather on Mars?", context=ctx_empty)
    print(f"RAG no-context query: {resp_no_context.answer[:40]}...")

    # RAG error
    rag_service_err = RagService(bedrock=bedrock_service_err, embeddings=embed_service, store=store)
    try:
        rag_service_err.query("trigger bedrock error", context=ctx_reader)
    except ClientError:
        pass

    # 8. Remaining security events
    sanitize_text("clean text\x00with control chars")
    telemetry.record_security_event("prompt_too_large", role="reader")
    telemetry.record_security_event("rls_violation", role="admin")

    # 9. Force flush telemetry to collector
    print("Flushing telemetry...")
    tracer_provider.force_flush()
    metric_reader.force_flush()
    meter_provider.force_flush()
    tracer_provider.shutdown()
    meter_provider.shutdown()
    print("Synthetic traffic generation completed successfully.")


if __name__ == "__main__":
    main()
