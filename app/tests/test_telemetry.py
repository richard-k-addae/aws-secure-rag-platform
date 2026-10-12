"""Telemetry foundation: off by default, bounded error types, no content leaves.

The leak tests instrument a real FastAPI app built from the real routers, send
requests carrying recognisable markers, and then search everything that would
be exported for those markers. Each one also checks the *unscrubbed* spans do
contain the marker, so a passing test cannot be an accident of the fixture.
"""
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import psycopg
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from app.api.dependencies import get_rag_service
from app.api.routes import documents, health, query
from app.auth.tenancy import TenantContext
from app.clients.bedrock import PromptTooLargeError
from app.core import telemetry
from app.core.logging import add_trace_context
from app.models.responses import Citation, QueryResponse
from app.tests.conftest import TENANT_A_HEADERS


def is_instrumented(app: FastAPI) -> bool:
    """The flag the FastAPI instrumentation sets on an app it has wrapped."""
    return bool(getattr(app, "_is_instrumented_by_opentelemetry", False))


QUESTION_MARK = "LEAKMARK_QUESTION_7731"
ANSWER_MARK = "LEAKMARK_ANSWER_4412"
QUERYSTRING_MARK = "LEAKMARK_QUERYSTRING_9087"
AWS_MESSAGE_MARK = "LEAKMARK_AWS_MESSAGE_3310"
SQL_MARK = "LEAKMARK_SQL_ROW_5526"
DATABASE_URL_MARK = "postgresql://rag_app:LEAKMARK_DB_PASSWORD_6604@db.internal:5432/rag"
TENANT_ID = TENANT_A_HEADERS["X-Tenant-Id"]

# The message Bedrock returned in the live M5 smoke run that failed and cleaned up.
LIVE_BEDROCK_MESSAGE = (
    "Model use case details have not been submitted for this account. "
    f"Fill out the Anthropic use case details form before using the model. {AWS_MESSAGE_MARK}"
)


def bedrock_error(code: str, message: str = LIVE_BEDROCK_MESSAGE) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "Converse")


class FakeRag:
    """Stands in for RagService: returns a marked answer, or raises what it was given."""

    def __init__(self, error: Exception | None = None) -> None:
        self._error = error

    def query(
        self, question: str, context: TenantContext, top_k: int | None = None
    ) -> QueryResponse:
        if self._error is not None:
            raise self._error
        return QueryResponse(
            request_id="req-1",
            answer=f"The answer is {ANSWER_MARK} [1]",
            citations=[Citation(source="policy.md", chunk_index=0, score=0.9)],
            model_id="test-model",
            input_tokens=8,
            output_tokens=4,
            latency_ms=1,
        )


@dataclass
class Harness:
    app: FastAPI
    client: TestClient
    raw: InMemorySpanExporter
    exported: InMemorySpanExporter
    tracer_provider: TracerProvider
    reader: InMemoryMetricReader

    def use(self, rag: FakeRag) -> None:
        self.app.dependency_overrides[get_rag_service] = lambda: rag

    def ask(self) -> int:
        response = self.client.post(
            f"/v1/query?note={QUERYSTRING_MARK}",
            json={"question": f"What is {QUESTION_MARK}?"},
            headers={**TENANT_A_HEADERS, "User-Agent": "leak-test"},
        )
        return int(response.status_code)

    def metric_points(self) -> dict[str, list[dict[str, Any]]]:
        points: dict[str, list[dict[str, Any]]] = {}
        data = self.reader.get_metrics_data()
        if data is None:
            return points
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    points[metric.name] = [
                        dict(point.attributes or {}) for point in metric.data.data_points
                    ]
        return points


def dump(spans: tuple[ReadableSpan, ...]) -> str:
    """Everything about a span that an exporter would send, as searchable text."""
    parts: list[str] = []
    for span in spans:
        parts.append(span.name)
        parts.append(repr(dict(span.attributes or {})))
        parts.append(repr(span.status.description))
        parts.append(repr(dict(span.resource.attributes)))
        for event in span.events:
            parts.append(event.name)
            parts.append(repr(dict(event.attributes or {})))
    return "\n".join(parts)


@pytest.fixture()
def harness() -> Iterator[Harness]:
    app = FastAPI(version="test")
    app.include_router(health.router)
    app.include_router(query.router, prefix="/v1")
    app.include_router(documents.router, prefix="/v1")

    raw, exported = InMemorySpanExporter(), InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(raw))
    tracer_provider.add_span_processor(
        SimpleSpanProcessor(telemetry.ScrubbingSpanExporter(exported))
    )
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader], views=telemetry.METRIC_VIEWS)

    telemetry.instrument_app(app, tracer_provider, meter_provider)
    # Guards the three "not instrumented" tests below against a silent false pass.
    assert is_instrumented(app) is True
    try:
        yield Harness(
            app=app,
            client=TestClient(app, raise_server_exceptions=False),
            raw=raw,
            exported=exported,
            tracer_provider=tracer_provider,
            reader=reader,
        )
    finally:
        FastAPIInstrumentor.uninstrument_app(app)
        tracer_provider.shutdown()
        meter_provider.shutdown()


# --- off unless an endpoint is configured ------------------------------------


@pytest.fixture()
def no_otel_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (*telemetry._ENDPOINT_VARIABLES, "OTEL_SDK_DISABLED", "OTEL_TRACES_EXPORTER"):
        monkeypatch.delenv(name, raising=False)


def test_telemetry_is_a_noop_without_an_endpoint(no_otel_env: None) -> None:
    app = FastAPI()
    assert telemetry.telemetry_enabled() is False
    assert telemetry.configure_telemetry(app) is False
    assert is_instrumented(app) is False


def test_an_endpoint_enables_telemetry(
    no_otel_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    assert telemetry.telemetry_enabled() is True


def test_sdk_disabled_overrides_an_endpoint(
    no_otel_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    app = FastAPI()
    assert telemetry.configure_telemetry(app) is False
    assert is_instrumented(app) is False


def test_the_real_app_is_not_instrumented_in_tests() -> None:
    """app.main calls configure_telemetry at import; with no endpoint it must do nothing."""
    from app.main import app

    assert is_instrumented(app) is False


def test_span_exporter_is_always_built_behind_the_scrubber() -> None:
    exporter = telemetry.build_span_exporter()
    try:
        assert isinstance(exporter, telemetry.ScrubbingSpanExporter)
    finally:
        exporter.shutdown()


# --- bounded error categories -------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (bedrock_error("ResourceNotFoundException"), "ResourceNotFoundException"),
        (bedrock_error("ThrottlingException"), "ThrottlingException"),
        (bedrock_error("AccessDeniedException"), "AccessDeniedException"),
        (bedrock_error("SomeBrandNewException"), "other_aws_error"),
        (bedrock_error(""), "other_aws_error"),
        (
            EndpointConnectionError(endpoint_url="https://example.invalid"),
            "EndpointConnectionError",
        ),
        (psycopg.OperationalError(f"connection failed {DATABASE_URL_MARK}"), "OperationalError"),
        (psycopg.errors.InsufficientPrivilege("row-level security"), "InsufficientPrivilege"),
        (psycopg.errors.UniqueViolation(f"Failing row contains ({SQL_MARK})"), "IntegrityError"),
        (PromptTooLargeError("too big"), "PromptTooLargeError"),
        (TimeoutError("slow"), "TimeoutError"),
        (RuntimeError(f"unexpected {DATABASE_URL_MARK}"), "other"),
        (KeyError(SQL_MARK), "other"),
    ],
)
def test_error_types_are_bounded_and_never_carry_the_message(
    exc: BaseException, expected: str
) -> None:
    result = telemetry.safe_error_type(exc)
    assert result == expected
    assert result in telemetry.ERROR_TYPES
    assert "LEAKMARK" not in result


def test_live_bedrock_failure_class_is_recorded_as_a_bounded_error_type(
    harness: Harness,
) -> None:
    """Regression for the live M5 failure: Converse raised ResourceNotFoundException.

    The span must carry exactly that category, and none of the provider's text.
    """
    exc = bedrock_error("ResourceNotFoundException")
    tracer = harness.tracer_provider.get_tracer("test")
    with tracer.start_as_current_span("chat test-model") as span:
        assert telemetry.record_error(span, exc) == "ResourceNotFoundException"

    (exported,) = harness.exported.get_finished_spans()
    assert dict(exported.attributes or {}) == {"error.type": "ResourceNotFoundException"}
    assert exported.status.status_code.name == "ERROR"
    assert exported.status.description is None
    assert list(exported.events) == []
    # record_error stores no message at all, so even the unscrubbed span is clean.
    assert AWS_MESSAGE_MARK not in dump(harness.raw.get_finished_spans())
    assert "use case" not in dump(harness.exported.get_finished_spans())


# --- nothing sensitive is exported --------------------------------------------


def test_successful_query_exports_no_content_or_identifiers(harness: Harness) -> None:
    harness.use(FakeRag())
    assert harness.ask() == 200

    raw, exported = dump(harness.raw.get_finished_spans()), dump(
        harness.exported.get_finished_spans()
    )
    # Control: the instrumentation really did capture the query string.
    assert QUERYSTRING_MARK in raw

    for marker in (QUESTION_MARK, ANSWER_MARK, QUERYSTRING_MARK, TENANT_ID, "leak-test"):
        assert marker not in exported
    for marker in (QUESTION_MARK, ANSWER_MARK, QUERYSTRING_MARK, TENANT_ID):
        assert marker not in repr(harness.metric_points())


def test_exported_span_attributes_are_only_allowlisted_keys(harness: Harness) -> None:
    harness.use(FakeRag())
    harness.ask()

    (span,) = harness.exported.get_finished_spans()
    assert span.name == "POST /v1/query"
    assert set(span.attributes or {}) <= telemetry.SAFE_SPAN_ATTRIBUTES
    assert (span.attributes or {})["http.route"] == "/v1/query"
    assert (span.attributes or {})["http.response.status_code"] == 200


@pytest.mark.parametrize(
    ("error", "marker", "exception_type"),
    [
        (bedrock_error("ResourceNotFoundException"), AWS_MESSAGE_MARK, "ClientError"),
        (
            psycopg.errors.UniqueViolation(
                f"duplicate key\nDETAIL: Failing row contains ({SQL_MARK}) on {DATABASE_URL_MARK}"
            ),
            SQL_MARK,
            "UniqueViolation",
        ),
    ],
)
def test_unhandled_errors_export_the_exception_type_but_never_the_message(
    harness: Harness, error: Exception, marker: str, exception_type: str
) -> None:
    harness.use(FakeRag(error=error))
    assert harness.ask() == 500

    raw, exported = dump(harness.raw.get_finished_spans()), dump(
        harness.exported.get_finished_spans()
    )
    # Control: without the scrubber the message and stack trace are captured.
    assert marker in raw
    assert "exception.stacktrace" in raw

    for forbidden in (
        marker,
        AWS_MESSAGE_MARK,
        SQL_MARK,
        DATABASE_URL_MARK,
        "LEAKMARK",
        "postgresql://",
        "Traceback",
        "exception.message",
        "exception.stacktrace",
        TENANT_ID,
    ):
        assert forbidden not in exported

    (span,) = harness.exported.get_finished_spans()
    assert span.status.status_code.name == "ERROR"
    assert span.status.description is None
    (event,) = span.events
    assert event.name == "exception"
    assert set(event.attributes or {}) == {"exception.type"}
    assert str((event.attributes or {})["exception.type"]).endswith(exception_type)


def test_unreviewed_span_attributes_are_dropped(harness: Harness) -> None:
    """Fail closed: an attribute nobody added to the allowlist never leaves."""
    tracer = harness.tracer_provider.get_tracer("test")
    with tracer.start_as_current_span("rag.query") as span:
        span.set_attribute("gen_ai.prompt", f"What is {QUESTION_MARK}?")
        span.set_attribute("db.statement", f"SELECT content -- {SQL_MARK}")
        span.set_attribute("tenant.id", TENANT_ID)
        span.set_attribute("database.url", DATABASE_URL_MARK)
        span.set_attribute("url.query", QUERYSTRING_MARK)
        span.set_attribute("http.route", "/v1/query")
        span.add_event("retrieved", {"content": ANSWER_MARK})

    (exported,) = harness.exported.get_finished_spans()
    assert dict(exported.attributes or {}) == {"http.route": "/v1/query"}
    assert list(exported.events) == []
    assert "LEAKMARK" not in dump(harness.exported.get_finished_spans())
    assert TENANT_ID not in dump(harness.exported.get_finished_spans())


# --- health probes and metric dimensions --------------------------------------


def test_health_probe_is_not_traced(harness: Harness) -> None:
    assert harness.client.get("/healthz").status_code == 200
    assert harness.exported.get_finished_spans() == ()
    assert harness.raw.get_finished_spans() == ()


def test_only_the_request_duration_metric_is_exported_with_bounded_dimensions(
    harness: Harness,
) -> None:
    harness.use(FakeRag())
    harness.client.post(
        "/v1/query",
        json={"question": "anything"},
        headers={**TENANT_A_HEADERS, "Host": "attacker-controlled.example"},
    )
    harness.client.get("/healthz")

    points = harness.metric_points()
    assert set(points) == {"http.server.request.duration"}
    allowed = {"error.type", "http.request.method", "http.response.status_code", "http.route"}
    for attributes in points["http.server.request.duration"]:
        assert set(attributes) <= allowed
        assert attributes.get("http.route") != "/healthz"
    assert "attacker-controlled" not in repr(points)


# --- log correlation ----------------------------------------------------------


def test_logs_gain_trace_and_span_ids_only_inside_a_span(harness: Harness) -> None:
    assert add_trace_context(None, "info", {"event": "outside"}) == {"event": "outside"}

    tracer = harness.tracer_provider.get_tracer("test")
    with tracer.start_as_current_span("rag.query") as span:
        event = add_trace_context(None, "info", {"event": "inside"})
        context = span.get_span_context()

    assert event["trace_id"] == format(context.trace_id, "032x")
    assert event["span_id"] == format(context.span_id, "016x")
    assert set(event) == {"event", "trace_id", "span_id"}
