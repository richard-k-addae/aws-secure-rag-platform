"""Input-hardening helpers.

First-line checks applied to every untrusted string that reaches the model:
the caller's question, retrieved chunk content and retrieved source names.
These complement - never replace - the structural prompt boundary in
app/rag/prompting.py and the evaluation suites in evaluations/security/.
"""
import re

from app.core.telemetry import record_security_event

# Characters that are invisible or reorder text, so they can hide or disguise
# instructions from a reviewer without changing what the model reads. Kept
# narrow on purpose: ZWJ/ZWNJ (emoji sequences, Persian and Indic scripts)
# and the LRM/RLM/ALM directional marks are legitimate in ordinary text and
# are preserved. Defined by code point so this file stays pure ASCII.
STRIPPED_CODE_POINT_RANGES: tuple[tuple[int, int], ...] = (
    (0x0000, 0x0008),  # C0 controls, except TAB, LF and CR
    (0x000B, 0x000C),
    (0x000E, 0x001F),
    (0x007F, 0x009F),  # DEL and C1 controls
    (0x200B, 0x200B),  # zero-width space
    (0x202A, 0x202E),  # bidi embeddings and overrides (LRE, RLE, PDF, LRO, RLO)
    (0x2060, 0x2064),  # word joiner and invisible operators
    (0x2066, 0x2069),  # bidi isolates (LRI, RLI, FSI, PDI)
    (0xFEFF, 0xFEFF),  # zero-width no-break space / BOM
    (0xE0000, 0xE007F),  # Unicode tag characters
)

CONTROL_CHARS = re.compile(
    "["
    + "".join(
        f"{re.escape(chr(start))}-{re.escape(chr(end))}"
        for start, end in STRIPPED_CODE_POINT_RANGES
    )
    + "]"
)


def sanitize_text(text: str) -> str:
    """Strip characters that can hide or reorder instructions; record that it happened."""
    sanitized = CONTROL_CHARS.sub("", text)
    if sanitized != text:
        record_security_event("input_sanitized")
    return sanitized


def exceeds_limit(text: str, max_chars: int) -> bool:
    return len(text) > max_chars
