"""OpenTelemetry foundation: vendor-neutral, off by default, fail-closed on content.

The application only ever speaks OTLP to a collector. Where telemetry goes
after that (CloudWatch in AWS, Prometheus locally) is the collector's
concern, so nothing here knows about a backend.

Three rules are enforced in this module rather than left to call sites:

* **No endpoint, no telemetry.** Without an OTLP endpoint in the environment
  nothing is installed: no SDK providers, no middleware, no exporter threads.
* **Spans are scrubbed on the way out.** Every exported span passes through
  an allowlist. Attributes that are not explicitly safe are dropped, exception
  events keep only the exception type, and status descriptions are removed.
  Auto-instrumentation would otherwise export exception messages, stack
  traces, query strings and client addresses.
* **Error categories are bounded.** `safe_error_type` maps any exception to a
  member of a fixed set. Messages never become attribute values: they can
  carry SQL, row content, connection strings or provider text.

Prompts, answers, retrieved content, embeddings, SQL, DATABASE_URL, tenant
identifiers and raw exception messages must never appear in telemetry.
"""
import os
from collections.abc import Sequence

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.metrics.view import DropAggregation, View
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import Event, ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.trace import Span, Status, StatusCode

from app.core.config import Settings, get_settings

SERVICE_NAME = "aws-secure-rag-platform"

_ENDPOINT_VARIABLES = (
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
)

# Liveness probes would otherwise dominate every trace view.
EXCLUDED_URLS = "healthz"

# --- bounded error categories -------------------------------------------------

OTHER_ERROR = "other"
OTHER_AWS_ERROR = "other_aws_error"

# AWS error codes worth telling apart. ResourceNotFoundException is what
# Bedrock returns when model access or use-case details are missing for the
# account, which is an operator problem, not a caller problem.
AWS_ERROR_CODES = frozenset(
    {
        "AccessDeniedException",
        "InternalServerException",
        "ModelErrorException",
        "ModelNotReadyException",
        "ModelTimeoutException",
        "ResourceNotFoundException",
        "ServiceQuotaExceededException",
        "ServiceUnavailableException",
        "ThrottlingException",
        "TooManyRequestsException",
        "ValidationException",
    }
)

# Matched against the exception's class hierarchy, most specific first, so
# a subclass reports as its nearest listed ancestor.
EXCEPTION_CLASS_NAMES = frozenset(
    {
        # botocore transport failures (no AWS error code exists for these)
        "ConnectTimeoutError",
        "EndpointConnectionError",
        "ReadTimeoutError",
        # psycopg
        "DataError",
        "InsufficientPrivilege",  # SQLSTATE 42501: includes row-security violations
        "IntegrityError",
        "InterfaceError",
        "InternalError",
        "OperationalError",  # includes connection failures
        "ProgrammingError",
        # application and builtins
        "PromptTooLargeError",
        "TimeoutError",
        "ValueError",
    }
)

ERROR_TYPES = AWS_ERROR_CODES | EXCEPTION_CLASS_NAMES | {OTHER_ERROR, OTHER_AWS_ERROR}


def safe_error_type(exc: BaseException) -> str:
    """Map an exception to one of ERROR_TYPES. Never returns message text."""
    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code", ""))
        return code if code in AWS_ERROR_CODES else OTHER_AWS_ERROR
    for cls in type(exc).__mro__:
        if cls.__name__ in EXCEPTION_CLASS_NAMES:
            return cls.__name__
    if isinstance(exc, BotoCoreError):
        return OTHER_AWS_ERROR
    return OTHER_ERROR


def record_error(span: Span, exc: BaseException) -> str:
    """Mark a span failed with a bounded category and nothing else.

    Use this instead of `span.record_exception`, which stores the exception
    message and stack trace.
    """
    error_type = safe_error_type(exc)
    span.set_attribute("error.type", error_type)
    span.set_status(Status(StatusCode.ERROR))
    return error_type


# --- span scrubbing -----------------------------------------------------------

# Exact keys only, no prefixes: a new attribute is dropped until it is
# reviewed and added here. Deliberately absent: url.query, url.path,
# client.address, user_agent.original, server.address, anything tenant-,
# document- or request-scoped, and anything that carries content or SQL.
SAFE_SPAN_ATTRIBUTES = frozenset(
    {
        "error.type",
        "http.request.method",
        "http.response.status_code",
        "http.route",
        "network.protocol.version",
        "url.scheme",
    }
)

_EXCEPTION_EVENT = "exception"
_EXCEPTION_TYPE = "exception.type"


def _scrub(span: ReadableSpan) -> ReadableSpan:
    attributes = {
        key: value for key, value in (span.attributes or {}).items() if key in SAFE_SPAN_ATTRIBUTES
    }
    events = [
        Event(
            _EXCEPTION_EVENT,
            {_EXCEPTION_TYPE: str((event.attributes or {}).get(_EXCEPTION_TYPE, OTHER_ERROR))},
            timestamp=event.timestamp,
        )
        for event in span.events
        if event.name == _EXCEPTION_EVENT
    ]
    return ReadableSpan(
        name=span.name,
        context=span.context,
        parent=span.parent,
        resource=span.resource,
        attributes=attributes,
        events=events,
        links=(),
        kind=span.kind,
        status=Status(span.status.status_code),
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )


class ScrubbingSpanExporter(SpanExporter):
    """Wraps an exporter so that only allowlisted span data ever leaves the process."""

    def __init__(self, inner: SpanExporter) -> None:
        self._inner = inner

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        return self._inner.export([_scrub(span) for span in spans])

    def shutdown(self) -> None:
        self._inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._inner.force_flush(timeout_millis)


# --- metric views -------------------------------------------------------------

# One HTTP instrument is kept, with bounded dimensions. The other instruments
# the FastAPI instrumentation creates are dropped: each metric and each
# dimension combination is billed and stored separately downstream.
METRIC_VIEWS: tuple[View, ...] = (
    View(
        instrument_name="http.server.request.duration",
        attribute_keys={
            "error.type",
            "http.request.method",
            "http.response.status_code",
            "http.route",
        },
    ),
    View(instrument_name="http.server.active_requests", aggregation=DropAggregation()),
    View(instrument_name="http.server.request.body.size", aggregation=DropAggregation()),
    View(instrument_name="http.server.response.body.size", aggregation=DropAggregation()),
)


# --- setup ----------------------------------------------------------------------


def telemetry_enabled() -> bool:
    """True only when the SDK is not disabled and an OTLP endpoint is configured."""
    if os.environ.get("OTEL_SDK_DISABLED", "").strip().lower() == "true":
        return False
    return any(os.environ.get(name, "").strip() for name in _ENDPOINT_VARIABLES)


def build_resource(settings: Settings, version: str) -> Resource:
    return Resource.create(
        {
            "service.name": SERVICE_NAME,
            "service.version": version,
            "deployment.environment.name": settings.app_env,
        }
    )


def build_span_exporter() -> SpanExporter:
    """The only way a span exporter is built: always behind the scrubber."""
    return ScrubbingSpanExporter(OTLPSpanExporter())


def instrument_app(
    app: FastAPI, tracer_provider: TracerProvider, meter_provider: MeterProvider
) -> None:
    """Attach HTTP server spans and metrics to the app, excluding health probes."""
    # Stable HTTP semantic conventions (http.request.method, http.route, ...).
    os.environ.setdefault("OTEL_SEMCONV_STABILITY_OPT_IN", "http")
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        excluded_urls=EXCLUDED_URLS,
        exclude_spans=["receive", "send"],
    )


def configure_telemetry(app: FastAPI) -> bool:
    """Install telemetry if an OTLP endpoint is configured. Returns whether it did."""
    if not telemetry_enabled():
        return False

    resource = build_resource(get_settings(), app.version)

    # A tracer provider always exists when enabled, so logs carry trace ids
    # even where span export is switched off (OTEL_TRACES_EXPORTER=none).
    tracer_provider = TracerProvider(resource=resource)
    if os.environ.get("OTEL_TRACES_EXPORTER", "").strip().lower() != "none":
        tracer_provider.add_span_processor(BatchSpanProcessor(build_span_exporter()))

    meter_provider = MeterProvider(
        metric_readers=[PeriodicExportingMetricReader(OTLPMetricExporter())],
        resource=resource,
        views=METRIC_VIEWS,
    )

    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(meter_provider)
    instrument_app(app, tracer_provider, meter_provider)
    return True
