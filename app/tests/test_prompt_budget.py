"""Prompt budget vs. user input limits (M7.2).

The 8,000-character user-message budget is kept (the system prompt is not
counted, as before). Retrieved passages are fitted into what the question
and the trusted framing leave over, so retrieval volume and framing overhead
are never reported as the caller's prompt_too_large.

The 4,000-character question limit is enforced twice: the public QueryRequest
schema rejects longer questions with 422 before the handler runs, and
RagService rejects them for direct callers before any retrieval
(QuestionTooLargeError -> 413 + prompt_too_large when routed).
"""
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pytest import MonkeyPatch

from app.api.dependencies import get_rag_service
from app.clients.bedrock import BedrockService
from app.core import telemetry
from app.core.config import MAX_QUESTION_CHARS, Settings, get_settings
from app.main import app
from app.rag.prompting import (
    PromptBudgetConfigError,
    QuestionTooLargeError,
    frame_user_prompt,
)
from app.rag.retrieval import RetrievedChunk
from app.rag.service import NO_CONTEXT_ANSWER, RagService
from app.tests.conftest import TENANT_A_HEADERS, context
from app.tests.prompt_frame import parse_framed_prompt

SETTINGS = get_settings()
BUDGET = SETTINGS.max_input_chars
# The chunker can carry overlap into a chunk, so this is the true maximum.
WORST_CHUNK_CHARS = SETTINGS.chunk_max_chars + SETTINGS.chunk_overlap_chars + 2
MAX_SOURCE_CHARS = 512  # IngestRequest.source max_length

client = TestClient(app)


def full_chunks(count: int) -> list[RetrievedChunk]:
    return [
        RetrievedChunk(
            source=f"synthetic-rank-{rank:02d}.md",
            chunk_index=rank,
            content=f"SYNTHETIC rank {rank:02d} " + "x" * (WORST_CHUNK_CHARS - 22),
            score=round(1.0 - rank / 100, 2),
        )
        for rank in range(count)
    ]


def security_events(monkeypatch: MonkeyPatch) -> list[dict[str, str]]:
    seen: list[dict[str, str]] = []
    monkeypatch.setattr(telemetry.SECURITY_EVENTS, "add", lambda v, a: seen.append(dict(a)))
    return seen


def query(
    question: str,
    chunks: list[RetrievedChunk],
    service_settings: Any = None,
    http: TestClient = client,
) -> tuple[Any, MagicMock, MagicMock]:
    fake = MagicMock()
    fake.converse.return_value = {
        "output": {"message": {"content": [{"text": "SYNTHETIC answer [1]"}]}},
        "usage": {"inputTokens": 1, "outputTokens": 1},
    }
    embeddings = MagicMock()
    embeddings.embed.return_value = [0.1]
    store = MagicMock()
    store.search.return_value = chunks
    service = RagService(bedrock=BedrockService(client=fake), embeddings=embeddings, store=store)
    if service_settings is not None:
        service._settings = service_settings
    app.dependency_overrides[get_rag_service] = lambda: service
    try:
        response = http.post("/v1/query", json={"question": question}, headers=TENANT_A_HEADERS)
    finally:
        app.dependency_overrides.pop(get_rag_service)
    return response, fake, store


# --- the guarantee the limits are chosen for ---------------------------------


def test_max_question_always_leaves_room_for_one_worst_case_passage() -> None:
    worst = RetrievedChunk(
        source='"' * MAX_SOURCE_CHARS,  # every character doubles under JSON escaping
        chunk_index=0,
        content="x" * WORST_CHUNK_CHARS,
        score=0.9,
    )
    framed = frame_user_prompt("q" * SETTINGS.max_question_chars, [worst], budget=BUDGET)
    assert framed.included == [worst]
    assert len(framed.text) <= BUDGET


# --- ordinary capacity does not depend on top_k ------------------------------


@pytest.mark.parametrize("top_k", [1, 5, 20])
@pytest.mark.parametrize("question_chars", [200, SETTINGS.max_question_chars])
def test_full_retrieval_is_fitted_not_blamed_on_the_user(
    monkeypatch: MonkeyPatch, top_k: int, question_chars: int
) -> None:
    events = security_events(monkeypatch)
    question = "SYNTHETIC question " + "q" * (question_chars - 19)
    chunks = full_chunks(top_k)

    response, fake, _ = query(question, chunks)

    assert response.status_code == 200
    assert events == []
    fake.converse.assert_called_once()
    sent = fake.converse.call_args.kwargs["messages"][0]["content"][0]["text"]
    assert len(sent) <= BUDGET
    frame = parse_framed_prompt(sent)
    assert frame.questions == [question]
    included = len(frame.passages)
    assert 1 <= included <= top_k
    # Highest-ranked passages first, in order, whole.
    assert [p.source for p in frame.passages] == [c.source for c in chunks[:included]]
    assert [p.content for p in frame.passages] == [c.content for c in chunks[:included]]
    # Citations describe exactly what the model was given.
    assert [c["source"] for c in response.json()["citations"]] == [
        c.source for c in chunks[:included]
    ]


# --- the public question contract matches the runtime limit ------------------


def test_openapi_advertises_the_enforced_question_limit() -> None:
    question = app.openapi()["components"]["schemas"]["QueryRequest"]["properties"]["question"]
    assert question["maxLength"] == MAX_QUESTION_CHARS == SETTINGS.max_question_chars == 4000
    assert question["minLength"] == 1


def test_settings_may_tighten_but_never_loosen_the_published_limit() -> None:
    assert Settings(max_question_chars=3000).max_question_chars == 3000
    with pytest.raises(ValidationError):
        Settings(max_question_chars=MAX_QUESTION_CHARS + 1)


def test_question_at_the_limit_is_accepted_over_http() -> None:
    response, fake, _ = query("q" * MAX_QUESTION_CHARS, full_chunks(1))
    assert response.status_code == 200
    fake.converse.assert_called_once()


def test_question_over_the_limit_is_rejected_at_the_api_boundary(
    monkeypatch: MonkeyPatch,
) -> None:
    """Schema validation (422), like every other contract violation: no service work.

    No prompt_too_large event: the request never reaches the handler, exactly
    as for any other schema violation.
    """
    events = security_events(monkeypatch)
    response, fake, store = query("q" * (MAX_QUESTION_CHARS + 1), full_chunks(5))
    assert response.status_code == 422
    assert events == []
    store.search.assert_not_called()
    fake.converse.assert_not_called()


# --- defense in depth for callers that bypass the schema ---------------------


def _direct_service() -> tuple[RagService, MagicMock, MagicMock, MagicMock]:
    fake = MagicMock()
    fake.converse.return_value = {
        "output": {"message": {"content": [{"text": "SYNTHETIC answer [1]"}]}},
        "usage": {"inputTokens": 1, "outputTokens": 1},
    }
    embeddings = MagicMock()
    embeddings.embed.return_value = [0.1]
    store = MagicMock()
    store.search.return_value = full_chunks(1)
    service = RagService(bedrock=BedrockService(client=fake), embeddings=embeddings, store=store)
    return service, fake, embeddings, store


def test_direct_service_accepts_a_question_at_the_limit() -> None:
    service, fake, _, _ = _direct_service()
    result = service.query("q" * MAX_QUESTION_CHARS, context=context())
    assert result.citations
    fake.converse.assert_called_once()


def test_direct_service_rejects_an_oversized_question_before_any_work() -> None:
    service, fake, embeddings, store = _direct_service()
    with pytest.raises(QuestionTooLargeError):
        service.query("q" * (MAX_QUESTION_CHARS + 1), context=context())
    embeddings.embed.assert_not_called()
    store.search.assert_not_called()
    fake.converse.assert_not_called()


def test_service_question_error_maps_to_413_and_one_bounded_event(
    monkeypatch: MonkeyPatch,
) -> None:
    events = security_events(monkeypatch)
    failing = MagicMock()
    failing.query.side_effect = QuestionTooLargeError("too large")
    app.dependency_overrides[get_rag_service] = lambda: failing
    try:
        response = client.post("/v1/query", json={"question": "q"}, headers=TENANT_A_HEADERS)
    finally:
        app.dependency_overrides.pop(get_rag_service)
    assert response.status_code == 413
    assert events == [{"event": "prompt_too_large", "role": "reader"}]


# --- non-user size conditions ------------------------------------------------


def test_context_that_cannot_fit_is_refused_without_blame(monkeypatch: MonkeyPatch) -> None:
    events = security_events(monkeypatch)
    oversized = RetrievedChunk(source="huge.md", chunk_index=0, content="x" * BUDGET, score=0.9)
    response, fake, _ = query("What is X?", [oversized, *full_chunks(2)])
    assert response.status_code == 200
    assert response.json()["answer"] == NO_CONTEXT_ANSWER
    assert response.json()["citations"] == []
    assert events == []
    fake.converse.assert_not_called()


def test_empty_retrieval_refusal_is_unchanged(monkeypatch: MonkeyPatch) -> None:
    events = security_events(monkeypatch)
    response, fake, _ = query("What is X?", [])
    assert response.status_code == 200
    assert response.json()["answer"] == NO_CONTEXT_ANSWER
    assert events == []
    fake.converse.assert_not_called()


def test_framing_larger_than_budget_is_a_configuration_fault(monkeypatch: MonkeyPatch) -> None:
    events = security_events(monkeypatch)
    tiny = SETTINGS.model_copy(update={"max_input_chars": 100})
    response, fake, _ = query(
        "What is X?",
        full_chunks(1),
        service_settings=tiny,
        http=TestClient(app, raise_server_exceptions=False),
    )
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert events == []
    fake.converse.assert_not_called()


# --- the fitter never produces malformed framing -----------------------------


def test_every_budget_yields_whole_ranked_passages_and_valid_tags() -> None:
    chunks = full_chunks(6)
    question = "What is X?"
    smallest = len(frame_user_prompt(question, [], budget=BUDGET).text)
    for budget in range(smallest, smallest + 6 * (WORST_CHUNK_CHARS + 150), 97):
        framed = frame_user_prompt(question, chunks, budget=budget)
        assert len(framed.text) <= budget
        frame = parse_framed_prompt(framed.text)
        assert frame.questions == [question]
        assert [p.source for p in frame.passages] == [c.source for c in framed.included]
        assert framed.included == chunks[: len(framed.included)]
        assert framed.text.count(f"<passage-{frame.token} ") == len(framed.included)
        assert framed.text.count(f"</passage-{frame.token}>") == len(framed.included)


def test_framing_and_question_limits_raise_the_right_errors() -> None:
    with pytest.raises(PromptBudgetConfigError):
        frame_user_prompt("q", full_chunks(1), budget=50)
    framing_only = len(frame_user_prompt("", [], budget=BUDGET).text)
    with pytest.raises(QuestionTooLargeError):
        frame_user_prompt("q" * 500, full_chunks(1), budget=framing_only + 100)


def test_question_error_reports_the_bounded_existing_error_type() -> None:
    assert telemetry.safe_error_type(QuestionTooLargeError("x")) == "PromptTooLargeError"
