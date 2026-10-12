"""Structured JSON logging with redaction-by-default.

Prompts and model responses are never logged unless LOG_FULL_CONTENT=true,
which is only permitted in dev mode with synthetic data. Production logs
carry metadata only: request IDs, token counts, latency, model ID.
"""
import logging
from collections.abc import MutableMapping
from typing import Any, cast

import structlog
from opentelemetry import trace

from app.core.config import get_settings


def add_trace_context(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Add trace_id and span_id so a log line can be joined to its trace.

    Adds nothing when there is no active span, which is always the case when
    telemetry is not configured.
    """
    context = trace.get_current_span().get_span_context()
    if context.is_valid:
        event_dict["trace_id"] = format(context.trace_id, "032x")
        event_dict["span_id"] = format(context.span_id, "016x")
    return event_dict


def configure_logging() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            add_trace_context,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level.upper(), logging.INFO)
        ),
    )


def get_logger(name: str) -> structlog.BoundLogger:
    return cast(structlog.BoundLogger, structlog.get_logger(name))
