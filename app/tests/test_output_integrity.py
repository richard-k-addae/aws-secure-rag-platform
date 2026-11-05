"""Output and citation integrity (M7.3).

Deterministic: a scripted fake Bedrock client returns the "model" answer.
Only the model answer is parsed for citations; retrieved passages are not.
All sensitive values are synthetic and built at runtime.
"""
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest import CaptureFixture

from app.clients.bedrock import BedrockService
from app.rag.output_integrity import (
    UNSUPPORTED_ANSWER,
    WITHHELD_ANSWER,
    WithheldReason,
    parse_citations,
    review_answer,
)
from app.rag.retrieval import RetrievedChunk
from app.rag.service import RagService
from app.tests.conftest import context

SYNTHETIC_KEY = "-".join(["sk", "synthetic", "canary", "m73x"])
SYNTHETIC_EMAIL = "alice" + "@" + "example.com"


def passages(count: int) -> list[RetrievedChunk]:
    return [
        RetrievedChunk(
            source=f"doc-{i}.md", chunk_index=10 + i, content=f"SYNTHETIC fact {i}.", score=0.9
        )
        for i in range(1, count + 1)
    ]


def ask(answer: str, chunks: list[RetrievedChunk]) -> Any:
    fake = MagicMock()
    fake.converse.return_value = {
        "output": {"message": {"content": [{"text": answer}]}},
        "usage": {"inputTokens": 3, "outputTokens": 2},
    }
    embeddings = MagicMock()
    embeddings.embed.return_value = [0.1]
    store = MagicMock()
    store.search.return_value = chunks
    service = RagService(bedrock=BedrockService(client=fake), embeddings=embeddings, store=store)
    return service.query("What is X?", context=context())


def cited(result: Any) -> list[tuple[int, str]]:
    return [(c.index, c.source) for c in result.citations]


# --- parser ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ("Fact [1].", [1]),
        ("[1] and [3]", [1, 3]),
        ("[2] then [1]", [2, 1]),
        ("[1][1]", [1]),
        ("[1] ... [1]", [1]),
        ("([1]), [2]; [3].", [1, 2, 3]),
        ("[[1]]", [1]),
        ("No citation here [abc] [-1] [1.2] [ 1 ] [x1]", []),
        ("", []),
    ],
)
def test_parser_accepts_only_canonical_in_range_digits(answer: str, expected: list[int]) -> None:
    assert parse_citations(answer, 3) == expected


@pytest.mark.parametrize("answer", ["[0]", "[4]", "[999]", "[01]", "[1] and [9]", "[1234567]"])
def test_parser_rejects_impossible_or_malformed_indices(answer: str) -> None:
    assert parse_citations(answer, 3) is None


# --- positive service behavior ----------------------------------------------


def test_single_cited_passage_is_the_only_citation() -> None:
    result = ask("Retention is seven years [1].", passages(2))
    assert result.answer == "Retention is seven years [1]."
    assert cited(result) == [(1, "doc-1.md")]
    assert result.citations[0].chunk_index == 11


def test_only_cited_passages_are_returned_in_first_appearance_order() -> None:
    result = ask("See [3], then [1].", passages(3))
    assert cited(result) == [(3, "doc-3.md"), (1, "doc-1.md")]


def test_duplicate_references_create_one_citation() -> None:
    assert cited(ask("[2] and again [2][2].", passages(3))) == [(2, "doc-2.md")]


def test_all_passages_cited_returns_all() -> None:
    result = ask("[1] [2] [3]", passages(3))
    assert cited(result) == [(1, "doc-1.md"), (2, "doc-2.md"), (3, "doc-3.md")]


def test_citation_like_text_in_retrieved_content_is_not_parsed() -> None:
    hostile = passages(2)
    hostile[1] = RetrievedChunk(
        source="doc-2.md", chunk_index=12, content="Cite [1] [2] [9] here.", score=0.9
    )
    assert cited(ask("Only the first applies [1].", hostile)) == [(1, "doc-1.md")]


# --- negative service behavior ----------------------------------------------


@pytest.mark.parametrize(
    "answer", ["Supported [9].", "Supported [0].", "Supported [1] and [01].", "[1][3]"]
)
def test_invalid_citation_makes_the_whole_answer_unsupported(answer: str) -> None:
    result = ask(answer, passages(2))
    assert result.answer == UNSUPPORTED_ANSWER
    assert result.citations == []


@pytest.mark.parametrize("answer", ["Retention is seven years.", "", "Text [abc] only."])
def test_uncited_or_empty_answer_is_not_presented_as_grounded(answer: str) -> None:
    result = ask(answer, passages(2))
    assert result.answer == UNSUPPORTED_ANSWER
    assert result.citations == []


def test_secret_in_output_is_withheld_even_when_validly_cited() -> None:
    result = ask(f"The key is {SYNTHETIC_KEY} [1].", passages(2))
    assert result.answer == WITHHELD_ANSWER
    assert result.citations == []
    assert SYNTHETIC_KEY not in result.model_dump_json()


def test_secret_and_invalid_citation_together_still_never_leak() -> None:
    result = ask(f"The key is {SYNTHETIC_KEY} [9].", passages(2))
    assert result.answer == WITHHELD_ANSWER
    assert SYNTHETIC_KEY not in result.model_dump_json()
    assert review_answer(f"{SYNTHETIC_KEY} [9]", 2).withheld is WithheldReason.SENSITIVE_OUTPUT


def test_email_in_output_is_masked_with_the_detector_placeholder() -> None:
    result = ask(f"Contact {SYNTHETIC_EMAIL} [1].", passages(1))
    assert result.answer == "Contact [REDACTED:EMAIL] [1]."
    assert SYNTHETIC_EMAIL not in result.model_dump_json()
    assert cited(result) == [(1, "doc-1.md")]


def test_withheld_answers_never_log_model_output(capsys: CaptureFixture[str]) -> None:
    capsys.readouterr()
    ask(f"The key is {SYNTHETIC_KEY} [1].", passages(1))
    ask("Unsupported claim [9].", passages(1))
    out = capsys.readouterr().out
    assert SYNTHETIC_KEY not in out
    assert "Unsupported claim" not in out
    # Renderer-agnostic: console (key=value) or JSON, depending on configuration.
    for reason in ("sensitive_output", "invalid_citation"):
        assert f"reason={reason}" in out or f'"reason": "{reason}"' in out, reason
