import http.server
import json
import threading
from typing import Any
from unittest.mock import MagicMock

import psycopg
from botocore.exceptions import ClientError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from pytest import CaptureFixture, MonkeyPatch

from app.api.dependencies import get_rag_service
from app.api.routes import documents, health, query
from app.auth.permissions import Classification, Role
from app.auth.tenancy import TenantContext
from app.clients.bedrock import BedrockService, PromptTooLargeError
from app.core import telemetry
from app.core.security import sanitize_text
from app.main import app as main_app
from app.rag.embeddings import EmbeddingService
from app.rag.ingestion import IngestionService
from app.rag.retrieval import RetrievedChunk, VectorStore
from app.rag.service import RagService
from app.tests.conftest import ADMIN_A_HEADERS, TENANT_A_HEADERS

PROMPT_SECRET_MARKER = "PROMPT_SECRET_781293"  # noqa: S105
ANSWER_SECRET_MARKER = "ANSWER_SECRET_981245"  # noqa: S105
RETRIEVED_CONTENT_MARKER = "RETRIEVED_CONTENT_671234"
TENANT_ID_MARKER = "TENANT_ID_SECRET_112233"
DOCUMENT_ID_MARKER = "DOCUMENT_ID_SECRET_445566"
SQL_TEXT_MARKER = "SQL_TEXT_SECRET_SELECT_STAR_FROM_SECRET"
POSTGRES_DETAIL_MARKER = "POSTGRES_DETAIL_SECRET_KEY_EXISTS"
AWS_ERROR_MESSAGE_MARKER = "AWS_ERROR_SECRET_BEDROCK_MESSAGE"
DATABASE_URL_MARKER = "postgres://secret_user:secret_pass@secret_host:5432/secret_db"


def test_unexpected_errors_return_generic_response_without_exception_detail(
    capsys: CaptureFixture[str],
) -> None:
    service = MagicMock()
    service.query.side_effect = psycopg.DatabaseError(
        f"{SQL_TEXT_MARKER}\n{POSTGRES_DETAIL_MARKER}"
    )
    main_app.dependency_overrides[get_rag_service] = lambda: service
    try:
        with TestClient(main_app, raise_server_exceptions=False) as client:
            response = client.post(
                "/v1/query",
                json={"question": "safe question"},
                headers=TENANT_A_HEADERS,
            )
    finally:
        main_app.dependency_overrides.pop(get_rag_service)

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    output = capsys.readouterr().out
    assert POSTGRES_DETAIL_MARKER not in output
    assert SQL_TEXT_MARKER not in output
    assert '"error_type": "other"' in output
    assert '"event": "unexpected_application_error"' in output


def test_structured_logs_remove_tenant_id_from_routine_events(
    capsys: CaptureFixture[str],
) -> None:
    context = TenantContext(
        tenant_id="tenant-secret-log",
        role=Role.READER,
        allowed_classifications=frozenset({Classification.PUBLIC}),
    )

    bedrock_mock = MagicMock()
    bedrock_mock.converse.return_value = {
        "output": {"message": {"content": [{"text": "safe answer"}]}},
        "usage": {"inputTokens": 5, "outputTokens": 5},
    }
    bedrock = BedrockService(client=bedrock_mock)

    embeddings_mock = MagicMock()
    embeddings_mock.invoke_model.return_value = {
        "body": MagicMock(read=lambda: json.dumps({"embedding": [0.1, 0.2]}))
    }
    embeddings = EmbeddingService(client=embeddings_mock)

    store_mock = MagicMock()
    store_mock.search.return_value = [
        RetrievedChunk(source="doc.md", chunk_index=0, content="fact", score=0.9)
    ]
    store_mock.upsert_chunks.return_value = 1
    store = store_mock

    rag = RagService(bedrock=bedrock, embeddings=embeddings, store=store)

    # 1. query_answered
    capsys.readouterr()
    rag.query("question 1", context=context)
    out = capsys.readouterr().out
    assert "query_answered" in out
    assert "tenant-secret-log" not in out
    assert '"role": "reader"' in out
    assert '"retrieved": 1' in out

    # 2. query_no_context
    store_mock.search.return_value = []
    rag.query("question 2", context=context)
    out = capsys.readouterr().out
    assert "query_no_context" in out
    assert "tenant-secret-log" not in out
    assert '"retrieved": 0' in out

    # 3. document_ingested
    ingestion = IngestionService(embeddings=embeddings, store=store)
    ingestion.ingest_text(
        tenant_id="tenant-secret-log",
        source="doc.md",
        classification=Classification.PUBLIC,
        text="sample text",
        authorize_as=None,
    )
    out = capsys.readouterr().out
    assert "document_ingested" in out
    assert "tenant-secret-log" not in out
    assert '"source": "doc.md"' in out
    assert '"classification": "public"' in out


def test_security_events_emitted_for_all_rejection_paths(monkeypatch: MonkeyPatch) -> None:
    events: list[dict[str, str]] = []
    monkeypatch.setattr(
        telemetry.SECURITY_EVENTS,
        "add",
        lambda val, attrs: events.append(attrs),
    )

    with TestClient(main_app, raise_server_exceptions=False) as client:
        # 1. missing_tenant
        resp = client.post("/v1/query", json={"question": "q"})
        assert resp.status_code == 401
        assert {"event": "missing_tenant"} in events

        # 2. unknown_tenant
        resp = client.post(
            "/v1/query",
            json={"question": "q"},
            headers={"X-Tenant-Id": "unknown-corp"},
        )
        assert resp.status_code == 403
        assert {"event": "unknown_tenant"} in events

        # 3. unknown_role
        resp = client.post(
            "/v1/query",
            json={"question": "q"},
            headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "superhero"},
        )
        assert resp.status_code == 403
        assert {"event": "unknown_role"} in events

        # 4. action_denied
        resp = client.post(
            "/v1/generate",
            json={"prompt": "p"},
            headers=TENANT_A_HEADERS,
        )
        assert resp.status_code == 403
        assert {"event": "action_denied", "role": "reader"} in events

        # 5. classification_denied
        resp = client.post(
            "/v1/documents/ingest",
            json={"source": "threat-intel.md", "classification": "restricted"},
            headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "ingestor"},
        )
        assert resp.status_code == 403
        assert {
            "event": "classification_denied",
            "role": "ingestor",
            "classification": "restricted",
        } in events

        # 6. path_rejected
        resp = client.post(
            "/v1/documents/ingest",
            json={"source": "../../escape.md", "classification": "internal"},
            headers=ADMIN_A_HEADERS,
        )
        assert resp.status_code == 400
        assert {"event": "path_rejected", "role": "admin"} in events

        # 7. prompt_too_large
        fake_rag = MagicMock()
        fake_rag.query.side_effect = PromptTooLargeError("too large")
        main_app.dependency_overrides[get_rag_service] = lambda: fake_rag
        try:
            resp = client.post(
                "/v1/query",
                json={"question": "q"},
                headers=TENANT_A_HEADERS,
            )
            assert resp.status_code == 413
            assert {"event": "prompt_too_large", "role": "reader"} in events
        finally:
            main_app.dependency_overrides.pop(get_rag_service)

        # 8. input_sanitized
        clean = sanitize_text("text\x00with\x1fcontrols")
        assert clean == "textwithcontrols"
        assert {"event": "input_sanitized"} in events

        # 9. rls_violation
        store = VectorStore(conninfo="postgresql://invalid:invalid@localhost:5432/rag")
        fake_conn = MagicMock()
        fake_conn.__enter__.return_value = fake_conn
        fake_cursor = MagicMock()
        fake_cursor.execute.side_effect = psycopg.errors.InsufficientPrivilege("42501 RLS")
        fake_conn.cursor.return_value.__enter__.return_value = fake_cursor
        monkeypatch.setattr(store, "_connect_as", lambda t: fake_conn)

        try:
            store.search(
                [0.1],
                context=TenantContext("t", Role.ADMIN, frozenset({Classification.PUBLIC})),
            )
        except psycopg.errors.InsufficientPrivilege:
            pass
        assert {"event": "rls_violation", "role": "admin"} in events


def test_manual_metric_proxy_multi_family_regression(monkeypatch: MonkeyPatch) -> None:
    calls: list[tuple[str, Any, dict[str, str]]] = []

    class Instrument:
        def __init__(self, name: str) -> None:
            self._name = name

        def record(self, value: float, attributes: dict[str, str]) -> None:
            calls.append((self._name, value, attributes))

        def add(self, value: int, attributes: dict[str, str]) -> None:
            calls.append((self._name, value, attributes))

    class Meter:
        def create_histogram(self, name: str, unit: str = "") -> Instrument:
            return Instrument(name)

        def create_counter(self, name: str) -> Instrument:
            return Instrument(name)

    monkeypatch.setattr(metrics, "get_meter", lambda name: Meter())

    telemetry.RAG_QUERY_DURATION.record(0.12, {"outcome": "answered", "role": "reader"})
    telemetry.GEN_AI_TOKEN_USAGE.record(42, {"token.type": "input", "outcome": "success"})
    telemetry.RAG_INGEST_CHUNKS.record(5, {"classification": "public", "outcome": "success"})
    telemetry.SECURITY_EVENTS.add(1, {"event": "missing_tenant"})

    assert calls == [
        ("rag.query.duration", 0.12, {"outcome": "answered", "role": "reader"}),
        ("gen_ai.client.token.usage", 42, {"token.type": "input", "outcome": "success"}),
        ("rag.ingest.chunks", 5, {"classification": "public", "outcome": "success"}),
        ("rag.security.events", 1, {"event": "missing_tenant"}),
    ]


def test_real_otlp_byte_capture_scrubs_all_sensitive_markers(monkeypatch: MonkeyPatch) -> None:
    captured_payloads: list[bytes] = []

    class CaptureHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", 0))
            data = self.rfile.read(length)
            captured_payloads.append(data)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), CaptureHandler)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    span_exporter = telemetry.ScrubbingSpanExporter(
        OTLPSpanExporter(endpoint=f"http://127.0.0.1:{port}/v1/traces")
    )
    metric_exporter = OTLPMetricExporter(endpoint=f"http://127.0.0.1:{port}/v1/metrics")
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    metric_reader = PeriodicExportingMetricReader(metric_exporter)
    meter_provider = MeterProvider(
        metric_readers=[metric_reader],
        views=telemetry.METRIC_VIEWS,
    )

    test_app = FastAPI(version="test-otlp")
    test_app.include_router(health.router)
    test_app.include_router(query.router, prefix="/v1")
    test_app.include_router(documents.router, prefix="/v1")

    telemetry.instrument_app(test_app, tracer_provider, meter_provider)

    monkeypatch.setattr(trace, "get_tracer", lambda name: tracer_provider.get_tracer(name))
    monkeypatch.setattr(metrics, "get_meter", lambda name: meter_provider.get_meter(name))

    try:
        # 1. Answered RAG query
        boto_embed_client = MagicMock()
        boto_embed_client.invoke_model.return_value = {
            "body": MagicMock(read=lambda: json.dumps({"embedding": [0.1, 0.2, 0.3]}))
        }
        embed_service = EmbeddingService(client=boto_embed_client)

        boto_bedrock_client = MagicMock()
        boto_bedrock_client.converse.return_value = {
            "output": {"message": {"content": [{"text": f"Grounded: {ANSWER_SECRET_MARKER}"}]}},
            "usage": {"inputTokens": 10, "outputTokens": 10},
        }
        bedrock_service = BedrockService(client=boto_bedrock_client)

        rag_store = VectorStore(conninfo=DATABASE_URL_MARKER)
        rag_conn = MagicMock()
        rag_conn.__enter__.return_value = rag_conn
        rag_cursor = MagicMock()
        rag_cursor.fetchall.return_value = [
            (
                "source.md",
                0,
                f"fact {RETRIEVED_CONTENT_MARKER}",
                DOCUMENT_ID_MARKER,
                TENANT_ID_MARKER,
                0.95,
            )
        ]
        rag_conn.cursor.return_value.__enter__.return_value = rag_cursor
        rag_store._connect_as = lambda t: rag_conn  # type: ignore[assignment]

        rag_service = RagService(bedrock=bedrock_service, embeddings=embed_service, store=rag_store)
        test_app.dependency_overrides[get_rag_service] = lambda: rag_service

        client = TestClient(test_app, raise_server_exceptions=False)
        resp = client.post(
            "/v1/query",
            json={"question": f"Question contains {PROMPT_SECRET_MARKER}"},
            headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "reader"},
        )
        assert resp.status_code == 200

        # 2. No-context query
        rag_cursor.fetchall.return_value = []
        resp = client.post(
            "/v1/query",
            json={"question": f"No context for {PROMPT_SECRET_MARKER}"},
            headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "reader"},
        )
        assert resp.status_code == 200

        # 3. Embedding success
        boto_embed_client = MagicMock()
        boto_embed_client.invoke_model.return_value = {
            "body": MagicMock(read=lambda: json.dumps({"embedding": [0.1, 0.2, 0.3]}))
        }
        embed_service = EmbeddingService(client=boto_embed_client)
        embed_service.embed(f"secret embedding text {PROMPT_SECRET_MARKER}")

        # 4. Bedrock simulated bounded AWS failure
        boto_bedrock_client = MagicMock()
        boto_bedrock_client.converse.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ResourceNotFoundException",
                    "Message": f"Model not found: {AWS_ERROR_MESSAGE_MARKER}",
                }
            },
            "Converse",
        )
        bedrock_service = BedrockService(client=boto_bedrock_client)
        try:
            bedrock_service.invoke("test prompt")
        except ClientError:
            pass

        # 5. Retrieval search & upsert
        store = VectorStore(conninfo=DATABASE_URL_MARKER)
        fake_conn = MagicMock()
        fake_cursor = MagicMock()
        fake_cursor.fetchall.return_value = [
            (
                "source.md",
                0,
                f"fact {RETRIEVED_CONTENT_MARKER}",
                DOCUMENT_ID_MARKER,
                TENANT_ID_MARKER,
                0.95,
            )
        ]
        fake_conn.cursor.return_value.__enter__.return_value = fake_cursor
        store._connect_as = lambda t: fake_conn  # type: ignore[assignment]
        ctx = TenantContext(TENANT_ID_MARKER, Role.READER, frozenset({Classification.PUBLIC}))
        store.search([0.1, 0.2], context=ctx)
        store.upsert_chunks(
            TENANT_ID_MARKER,
            "source.md",
            Classification.PUBLIC,
            [(0, f"content {RETRIEVED_CONTENT_MARKER}", [0.1, 0.2])],
            document_id=DOCUMENT_ID_MARKER,
            authorize_as=None,
        )

        # 6. Ingestion
        ingest_service = IngestionService(embeddings=embed_service, store=store)
        ingest_service.ingest_text(
            tenant_id=TENANT_ID_MARKER,
            source="source.md",
            classification=Classification.PUBLIC,
            text=f"secret content {RETRIEVED_CONTENT_MARKER}",
            document_id=DOCUMENT_ID_MARKER,
            authorize_as=None,
        )

        # 7. Security rejection
        resp = client.post(
            "/v1/generate",
            json={"prompt": "prompt"},
            headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "reader"},
        )
        assert resp.status_code == 403

        # 8. Sanitized server exception
        rag_conn.cursor.side_effect = psycopg.OperationalError(
            f"{SQL_TEXT_MARKER}\n{POSTGRES_DETAIL_MARKER}"
        )
        resp = client.post(
            "/v1/query",
            json={"question": "q"},
            headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "reader"},
        )
        assert resp.status_code == 503

        tracer_provider.force_flush()
        metric_reader.force_flush()
        meter_provider.force_flush()
    finally:
        tracer_provider.shutdown()
        meter_provider.shutdown()
        server.shutdown()
        server_thread.join(timeout=2.0)
        FastAPIInstrumentor.uninstrument_app(test_app)

    assert len(captured_payloads) > 0
    combined_bytes = b"".join(captured_payloads)

    # Privacy assertions: NO secret marker appears in raw exported OTLP bytes
    for marker in (
        PROMPT_SECRET_MARKER,
        ANSWER_SECRET_MARKER,
        RETRIEVED_CONTENT_MARKER,
        TENANT_ID_MARKER,
        DOCUMENT_ID_MARKER,
        SQL_TEXT_MARKER,
        POSTGRES_DETAIL_MARKER,
        AWS_ERROR_MESSAGE_MARKER,
        DATABASE_URL_MARKER,
    ):
        assert (
            marker.encode("utf-8") not in combined_bytes
        ), f"Marker leaked in OTLP bytes: {marker}"

    # Verifiable presence: safe telemetry fields ARE present
    assert b"rag.query" in combined_bytes
    assert b"rag.retrieval.search" in combined_bytes
    assert b"gen_ai" in combined_bytes
    assert b"rag.ingest" in combined_bytes
    assert b"error.type" in combined_bytes
    assert b"http.server.request.duration" in combined_bytes
