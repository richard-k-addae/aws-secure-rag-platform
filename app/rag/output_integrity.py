"""Output integrity for generated answers (M7.3).

The model's answer is untrusted output. Before it is returned:

1. Sensitive-output check (app.core.sensitive_data). A BLOCK finding
   (credential, national identifier) withholds the whole answer; a MASK
   finding (email) is redacted in place with the detector's own placeholder.
   This runs first so a sensitive value can never leave through any later
   branch, including a citation failure.
2. Citation validation. Only the syntax the prompt asks for is recognized:
   "[" digits "]". Every such token is a support claim and must be a
   canonical integer in 1..passages_given; one impossible or malformed
   claim ([0], [01], [9] with two passages) makes the answer unsupported.
   Bracketed text that is not all digits ([abc], [-1], [1.2]) is ordinary
   text, not a citation. An answer with no valid citation (including an
   empty answer) is unsupported. This is intentional: /v1/query presents its
   answers as grounded, cited RAG output, so uncited text is replaced by the
   fixed UNSUPPORTED_ANSWER with no citations rather than returned.
3. Citation selection. Cited indices in first-appearance order, duplicates
   removed. Nothing is substituted, renumbered or remapped.

Rejected answers are replaced by a fixed constant; the model text is never
echoed, logged or partially returned. Only the model answer is parsed:
retrieved passages are never read here.
"""
import re
from dataclasses import dataclass
from enum import StrEnum

from app.core.sensitive_data import Disposition, disposition, redact, scan

CITATION_TOKEN = re.compile(r"\[(\d+)\]")
_MAX_INDEX_DIGITS = 6

UNSUPPORTED_ANSWER = (
    "I cannot provide a supported answer from the available documents. "
    "The generated answer did not cite the provided passages validly."
)
WITHHELD_ANSWER = (
    "The generated answer was withheld because it did not pass output safety checks."
)


class WithheldReason(StrEnum):
    """Bounded reason a generated answer was not returned."""

    SENSITIVE_OUTPUT = "sensitive_output"
    INVALID_CITATION = "invalid_citation"
    UNCITED = "uncited"


@dataclass(frozen=True)
class ReviewedAnswer:
    answer: str
    cited: list[int]
    withheld: WithheldReason | None = None


def parse_citations(answer: str, passage_count: int) -> list[int] | None:
    """Return cited indices (first appearance, de-duplicated), or None if any is invalid."""
    cited: list[int] = []
    for match in CITATION_TOKEN.finditer(answer):
        digits = match.group(1)
        if len(digits) > _MAX_INDEX_DIGITS or digits != str(int(digits)):
            return None
        index = int(digits)
        if not 1 <= index <= passage_count:
            return None
        if index not in cited:
            cited.append(index)
    return cited


def review_answer(answer: str, passage_count: int) -> ReviewedAnswer:
    """Apply the output checks in their fixed order."""
    findings = scan(answer)
    verdict = disposition(findings)
    if verdict is Disposition.BLOCK:
        return ReviewedAnswer(WITHHELD_ANSWER, [], WithheldReason.SENSITIVE_OUTPUT)
    if verdict is Disposition.MASK:
        answer = redact(answer)

    cited = parse_citations(answer, passage_count)
    if cited is None:
        return ReviewedAnswer(UNSUPPORTED_ANSWER, [], WithheldReason.INVALID_CITATION)
    if not cited:
        return ReviewedAnswer(UNSUPPORTED_ANSWER, [], WithheldReason.UNCITED)
    return ReviewedAnswer(answer, cited)
