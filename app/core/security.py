"""Input-hardening helpers.

First-line request checks that run before any model call. These complement
- never replace - Bedrock Guardrails (Phase 5) and the prompt-injection
evaluation suite in evaluations/security/.
"""
import re

from app.core.telemetry import record_security_event

CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(text: str) -> str:
    """Strip control characters that can hide instructions from log review."""
    sanitized = CONTROL_CHARS.sub("", text)
    if sanitized != text:
        record_security_event("input_sanitized")
    return sanitized


def exceeds_limit(text: str, max_chars: int) -> bool:
    return len(text) > max_chars
