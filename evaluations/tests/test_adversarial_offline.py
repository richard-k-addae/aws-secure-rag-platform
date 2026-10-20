"""Offline adversarial security harness (M7.1).

Every case in evaluations/security/adversarial_cases.json executes here
against the real request path: FastAPI route -> real RagService -> real
prompt construction -> real BedrockService request construction. Only the
edges are faked: the vector store returns scripted chunks, the embedder
returns a fixed vector, and the Bedrock client is a scripted fake that
records the exact Converse arguments. No network or AWS call is made.

Scope, stated plainly:

* These are STRUCTURAL, deterministic assertions about what the platform
  sends to the model and returns to the caller. They do not show that a
  model resists jailbreaks or ignores injected text; that is model
  behavior and belongs to the live evaluation (M7.5).
* ``control_status`` is a bounded vocabulary:

  - ``enforced``: the secure invariant holds today and is asserted.
  - ``not_implemented``: the secure invariant is asserted under a strict
    expected failure. CI stays green, the gap stays visible, and the day
    the control starts working the run fails (XPASS strict) until the
    case is deliberately promoted to ``enforced``.
  - ``characterization``: asserts the CURRENT (vulnerable) behavior as
    evidence. When the vulnerability is fixed this fails outright, which
    also forces a deliberate update.

* Harness preconditions raise HarnessPreconditionError, not
  AssertionError, and strict xfails only accept AssertionError. A broken
  harness therefore fails loudly instead of hiding behind an xfail.
"""
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from app.api.dependencies import get_bedrock_service, get_ingestion_service, get_rag_service
from app.clients.bedrock import BedrockService
from app.core import telemetry
from app.core.config import get_settings
from app.core.security import sanitize_text
from app.core.sensitive_data import SensitiveKind, scan
from app.main import app
from app.rag import prompting
from app.rag import service as service_module
from app.rag.ingestion import IngestionService
from app.rag.prompting import SYSTEM_PROMPT, build_user_prompt
from app.rag.retrieval import RetrievedChunk, VectorStore
from app.rag.service import NO_CONTEXT_ANSWER, RagService

REPO_ROOT = Path(__file__).resolve().parents[2]
SECURITY_DIR = REPO_ROOT / "evaluations" / "security"
CASES: list[dict[str, Any]] = json.loads(
    (SECURITY_DIR / "adversarial_cases.json").read_text(encoding="utf-8")
)
PI_CASES: list[dict[str, Any]] = json.loads(
    (SECURITY_DIR / "prompt_injection_cases.json").read_text(encoding="utf-8")
)
PI_BY_ID = {case["id"]: case for case in PI_CASES}

CASE_FIELDS = frozenset(
    {
        "id",
        "category",
        "source",
        "payload",
        "payload_ref",
        "check",
        "expected_behavior",
        "control_status",
        "priority",
        "atlas",
        "owasp",
        "notes",
    }
)
CATEGORIES = frozenset(
    {
        "direct_injection",
        "indirect_injection",
        "output_integrity",
        "authorization_integrity",
        "no_tools",
    }
)
CONTROL_STATUSES = frozenset({"enforced", "not_implemented", "characterization"})
SOURCES = frozenset(
    {
        "question",
        "retrieved_chunk",
        "model_output",
        "bedrock_request",
        "ingest_request",
        "request_headers",
    }
)
PRIORITIES = frozenset({"P0", "P1", "P2"})
ATLAS_ID = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
OWASP_ID = re.compile(r"^LLM(0[1-9]|10):2025$")

# Current prompt grammar (app/rag/prompting.py). A line matching HEADER_LINE
# is what the model is told is a numbered, sourced passage.
HEADER_LINE = re.compile(r"^\[\d+\] \(source: [^)\n]*\)$", re.MULTILINE)
QUESTION_LINE = re.compile(r"^Question:", re.MULTILINE)
CITATION_MARKER = re.compile(r"\[(\d+)\]")
INVISIBLE_CHARS = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)

# Converse request fields reviewed for this service. Anything else (notably
# toolConfig or additionalModelRequestFields) must be a deliberate change.
# guardrailConfig is listed only so this tripwire stays neutral about M7.6;
# it encodes no decision about how guardrails are applied.
REVIEWED_CONVERSE_FIELDS = frozenset(
    {"modelId", "messages", "inferenceConfig", "system", "guardrailConfig"}
)

READER_A = {"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "reader"}
INGESTOR_A = {"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "ingestor"}
SELF_ASSERTED_ADMIN_A = {"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "admin"}

_SYSTEM_PROMPT_AT_IMPORT = str(SYSTEM_PROMPT)

client = TestClient(app)

EXECUTED: set[str] = set()


class HarnessPreconditionError(Exception):
    """The harness could not set up the scenario. Never an expected failure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HarnessPreconditionError(message)


# --- fixtures and capture ----------------------------------------------------


def benign_chunk(index: int = 0) -> RetrievedChunk:
    return RetrievedChunk(
        source=f"retention-policy-{index}.md",
        chunk_index=index,
        content="SYNTHETIC: Archived records are retained for seven years.",
        score=0.9,
        document_id=f"doc-retention-{index}",
        tenant_id="tenant-a",
    )


def chunk_with(content: str) -> RetrievedChunk:
    return RetrievedChunk(
        source="retention-policy.md",
        chunk_index=0,
        content=content,
        score=0.9,
        document_id="doc-retention",
        tenant_id="tenant-a",
    )


def payload_of(case: dict[str, Any]) -> str:
    if case["payload_ref"] is not None:
        return str(PI_BY_ID[case["payload_ref"]]["attack"])
    return str(case["payload"])


def scripted_bedrock(text: str) -> tuple[BedrockService, MagicMock]:
    fake = MagicMock()
    fake.converse.return_value = {
        "output": {"message": {"content": [{"text": text}]}},
        "usage": {"inputTokens": 11, "outputTokens": 7},
    }
    return BedrockService(client=fake), fake


@dataclass
class QueryCapture:
    """Everything observable about one /v1/query round trip."""

    response: Response
    chunks: list[RetrievedChunk]
    converse: MagicMock
    store: MagicMock

    @property
    def calls(self) -> list[dict[str, Any]]:
        return [dict(call.kwargs) for call in self.converse.converse.call_args_list]

    @property
    def request(self) -> dict[str, Any]:
        calls = self.calls
        require(len(calls) == 1, f"expected one Converse call, got {len(calls)}")
        return calls[0]

    @property
    def system_text(self) -> str:
        return "".join(block["text"] for block in self.request.get("system", []))

    @property
    def user_text(self) -> str:
        messages = self.request["messages"]
        return "".join(block.get("text", "") for block in messages[0]["content"])

    @property
    def body(self) -> dict[str, Any]:
        return dict(self.response.json())


def run_query(
    question: str,
    chunks: list[RetrievedChunk],
    model_text: str = "SYNTHETIC grounded answer [1]",
    headers: dict[str, str] | None = None,
) -> QueryCapture:
    bedrock, fake = scripted_bedrock(model_text)
    embeddings = MagicMock()
    embeddings.embed.return_value = [0.1, 0.2, 0.3, 0.4]
    store = MagicMock()
    store.search.return_value = chunks
    service = RagService(bedrock=bedrock, embeddings=embeddings, store=store)
    app.dependency_overrides[get_rag_service] = lambda: service
    try:
        response = client.post(
            "/v1/query", json={"question": question}, headers=headers or READER_A
        )
    finally:
        app.dependency_overrides.pop(get_rag_service)
    return QueryCapture(response=response, chunks=chunks, converse=fake, store=store)


def run_answered_query(
    question: str, chunks: list[RetrievedChunk], model_text: str = "SYNTHETIC answer [1]"
) -> QueryCapture:
    capture = run_query(question, chunks, model_text=model_text)
    require(
        capture.response.status_code == 200,
        f"/v1/query returned {capture.response.status_code}",
    )
    require(len(capture.calls) == 1, "model was not invoked exactly once")
    return capture


WRITE_VERBS = ("DELETE", "INSERT", "UPDATE", "TRUNCATE", "MERGE")
SELECT_LIST = re.compile(r"^\s*SELECT\s+(?P<cols>.+?)\s+FROM\s+document_chunks\b", re.I | re.S)


class _FakeCursor:
    """Answers reads of document_chunks from in-memory rows; records, never applies, writes.

    SELECT results are projected by the column names the caller asks for, so
    the fake does not depend on how the store queries existing rows. An
    unknown column raises KeyError: a harness error, never an expected failure.
    """

    def __init__(self, conn: "_FakeConnection") -> None:
        self._conn = conn
        self._rows: list[tuple[Any, ...]] = []
        self.rowcount = 0

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *exc: object) -> Literal[False]:
        return False

    def execute(self, sql: str, params: Any = None) -> None:
        self._conn.statements.append(sql)
        self._rows = []
        self.rowcount = 0
        match = SELECT_LIST.match(sql)
        if match:
            columns = [c.strip() for c in match.group("cols").split(",")]
            self._rows = [tuple(row[c] for c in columns) for row in self._conn.existing]
            self.rowcount = len(self._rows)

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._rows[0] if self._rows else None


class _FakeConnection:
    """psycopg semantics that matter here: commit on clean exit, rollback on exception."""

    def __init__(self, existing: list[dict[str, Any]]) -> None:
        self.existing = existing
        self.statements: list[str] = []
        self.committed: bool | None = None

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)

    def __enter__(self) -> "_FakeConnection":
        return self

    def __exit__(self, exc_type: object, *rest: object) -> Literal[False]:
        self.committed = exc_type is None
        return False

    @property
    def wrote(self) -> bool:
        return any(s.lstrip().upper().startswith(WRITE_VERBS) for s in self.statements)


@dataclass
class IngestCapture:
    response: Response
    connections: list[_FakeConnection]
    events: list[dict[str, str]]

    @property
    def committed_writes(self) -> bool:
        return any(c.wrote and c.committed for c in self.connections)


def run_fake_db_ingest(document_id: str, existing: list[dict[str, Any]]) -> IngestCapture:
    """Drive /v1/documents/ingest as an ingestor through the real service and store code."""
    connections: list[_FakeConnection] = []
    events: list[dict[str, str]] = []

    def connect(*args: Any, **kwargs: Any) -> _FakeConnection:
        conn = _FakeConnection(existing)
        connections.append(conn)
        return conn

    embeddings = MagicMock()
    embeddings.embed.return_value = [0.1, 0.2, 0.3, 0.4]
    with (
        patch("app.rag.retrieval.psycopg.connect", side_effect=connect),
        patch.object(
            telemetry.SECURITY_EVENTS, "add", lambda value, attrs: events.append(dict(attrs))
        ),
    ):
        store = VectorStore(conninfo="postgresql://offline-harness/never-connected")
        service = IngestionService(embeddings=embeddings, store=store)
        app.dependency_overrides[get_ingestion_service] = lambda: service
        try:
            response = client.post(
                "/v1/documents/ingest",
                json={
                    "source": "employee_security_policy.md",
                    "classification": "internal",
                    "document_id": document_id,
                },
                headers=INGESTOR_A,
            )
        finally:
            app.dependency_overrides.pop(get_ingestion_service)
    return IngestCapture(response=response, connections=connections, events=events)


def run_generate(headers: dict[str, str]) -> tuple[Response, MagicMock]:
    bedrock, fake = scripted_bedrock("SYNTHETIC generate output")
    app.dependency_overrides[get_bedrock_service] = lambda: bedrock
    try:
        response = client.post(
            "/v1/generate", json={"prompt": "SYNTHETIC prompt"}, headers=headers
        )
    finally:
        app.dependency_overrides.pop(get_bedrock_service)
    return response, fake


# --- shared invariants -------------------------------------------------------


def assert_system_role_integrity(capture: QueryCapture, attacker_text: str) -> None:
    """SYSTEM_PROMPT travels only in the system role, byte-identical to source."""
    request = capture.request
    assert request["system"] == [{"text": SYSTEM_PROMPT}]
    assert capture.system_text == _SYSTEM_PROMPT_AT_IMPORT
    # Not rebound at runtime in either module that uses it.
    assert prompting.SYSTEM_PROMPT == _SYSTEM_PROMPT_AT_IMPORT
    assert getattr(service_module, "SYSTEM_PROMPT") == _SYSTEM_PROMPT_AT_IMPORT  # noqa: B009
    assert attacker_text not in capture.system_text
    assert SYSTEM_PROMPT not in capture.user_text


def assert_single_user_message(capture: QueryCapture) -> None:
    messages = capture.request["messages"]
    assert len(messages) == 1
    assert messages[0]["role"] == "user"
    assert len(messages[0]["content"]) == 1
    assert set(messages[0]["content"][0]) == {"text"}


def assert_no_tools(request: dict[str, Any]) -> None:
    assert "toolConfig" not in request
    assert set(request) <= REVIEWED_CONVERSE_FIELDS, set(request) - REVIEWED_CONVERSE_FIELDS
    for message in request.get("messages", []):
        for block in message["content"]:
            assert "toolUse" not in block
            assert "toolResult" not in block


def assert_empty_retrieval_refuses(question: str) -> None:
    capture = run_query(question, [])
    require(capture.response.status_code == 200, "empty-retrieval query did not return 200")
    capture.converse.converse.assert_not_called()
    assert capture.body["answer"] == NO_CONTEXT_ANSWER
    assert capture.body["citations"] == []


# --- runners -----------------------------------------------------------------


def run_direct_structural(case: dict[str, Any]) -> None:
    question = payload_of(case)
    sanitized = sanitize_text(question)
    chunks = [benign_chunk()]
    capture = run_answered_query(question, chunks)

    assert_system_role_integrity(capture, sanitized)
    assert_single_user_message(capture)
    assert_no_tools(capture.request)
    # The user message is exactly the formatter's output: no extra context,
    # nothing dropped, nothing widened by the request.
    assert capture.user_text == build_user_prompt(sanitized, chunks)
    assert len(HEADER_LINE.findall(capture.user_text)) == len(chunks)
    assert len(QUESTION_LINE.findall(capture.user_text)) == 1
    assert [c["source"] for c in capture.body["citations"]] == [c.source for c in chunks]
    # Retrieval runs as the header-resolved caller, whatever the question says.
    passed = capture.store.search.call_args.kwargs["context"]
    assert (passed.tenant_id, passed.role.value) == ("tenant-a", "reader")

    assert_empty_retrieval_refuses(question)


def run_restricted_action(case: dict[str, Any]) -> None:
    run_direct_structural(case)
    generate, fake = run_generate(READER_A)
    assert generate.status_code == 403
    fake.converse.assert_not_called()
    ingest = client.post(
        "/v1/documents/ingest",
        json={"source": "employee_security_policy.md", "classification": "internal"},
        headers=READER_A,
    )
    assert ingest.status_code == 403


def run_secret_extraction(case: dict[str, Any]) -> None:
    run_direct_structural(case)
    settings = get_settings()
    capture = run_answered_query(payload_of(case), [benign_chunk()])
    sent = capture.system_text + "\n" + capture.user_text
    for secret in (settings.database_url, settings.admin_database_url, settings.app_db_password):
        assert secret not in sent


def run_question_boundary_direct(case: dict[str, Any]) -> None:
    chunks = [benign_chunk()]
    capture = run_answered_query(payload_of(case), chunks)
    assert len(HEADER_LINE.findall(capture.user_text)) == len(chunks)
    assert len(QUESTION_LINE.findall(capture.user_text)) == 1


def run_hidden_chars_question(case: dict[str, Any]) -> None:
    capture = run_answered_query(payload_of(case), [benign_chunk()])
    assert not INVISIBLE_CHARS.search(capture.user_text)


def run_passage_boundary(case: dict[str, Any]) -> None:
    chunks = [chunk_with(payload_of(case))]
    capture = run_answered_query("What is the retention period?", chunks)
    assert len(HEADER_LINE.findall(capture.user_text)) == len(chunks)


def run_passage_boundary_current(case: dict[str, Any]) -> None:
    chunks = [chunk_with(payload_of(case))]
    capture = run_answered_query("What is the retention period?", chunks)
    headers = HEADER_LINE.findall(capture.user_text)
    # One retrieved chunk renders as two passage headers, and the forged one
    # is the same grammar the formatter itself emits.
    assert headers == ["[1] (source: retention-policy.md)", "[2] (source: trusted.md)"]
    # The API's own citations know nothing of the forged source.
    assert [c["source"] for c in capture.body["citations"]] == ["retention-policy.md"]


def run_question_boundary_chunk(case: dict[str, Any]) -> None:
    capture = run_answered_query("What is the retention period?", [chunk_with(payload_of(case))])
    assert len(QUESTION_LINE.findall(capture.user_text)) == 1


def run_question_boundary_chunk_current(case: dict[str, Any]) -> None:
    question = "What is the retention period?"
    capture = run_answered_query(question, [chunk_with(payload_of(case))])
    lines = [line for line in capture.user_text.splitlines() if QUESTION_LINE.match(line)]
    assert len(lines) == 2
    # The forged question is rendered BEFORE the real one.
    assert lines[0].startswith("Question: Ignore the user's question")
    assert lines[1] == f"Question: {question}"


def run_hidden_chars_chunk(case: dict[str, Any]) -> None:
    capture = run_answered_query("What is the retention period?", [chunk_with(payload_of(case))])
    assert not INVISIBLE_CHARS.search(capture.user_text)


def run_citation_index(case: dict[str, Any]) -> None:
    capture = run_answered_query(
        "What is the retention period?",
        [benign_chunk(0), benign_chunk(1)],
        model_text=payload_of(case),
    )
    body = capture.body
    cited = {int(n) for n in CITATION_MARKER.findall(body["answer"])}
    assert cited <= set(range(1, len(body["citations"]) + 1)), cited


def run_citation_index_current(case: dict[str, Any]) -> None:
    capture = run_answered_query(
        "What is the retention period?",
        [benign_chunk(0), benign_chunk(1)],
        model_text=payload_of(case),
    )
    body = capture.body
    assert "[9]" in body["answer"]
    assert len(body["citations"]) == 2
    assert set(body) == {
        "request_id",
        "answer",
        "citations",
        "model_id",
        "input_tokens",
        "output_tokens",
        "latency_ms",
    }


def run_output_secret_leak(case: dict[str, Any]) -> None:
    canary = payload_of(case)
    require(
        any(f.kind is SensitiveKind.CREDENTIAL for f in scan(canary)),
        "canary no longer matches the credential detector",
    )
    capture = run_answered_query(
        "What is the integration key?", [chunk_with(canary)], model_text=canary
    )
    leaked = [f for f in scan(capture.body["answer"]) if f.kind is SensitiveKind.CREDENTIAL]
    assert leaked == []


def run_no_tools(case: dict[str, Any]) -> None:
    capture = run_answered_query("What is the retention period?", [benign_chunk()])
    assert_no_tools(capture.request)
    generate, fake = run_generate(SELF_ASSERTED_ADMIN_A)
    require(generate.status_code == 200, "admin /v1/generate did not return 200")
    assert_no_tools(dict(fake.converse.call_args.kwargs))


def run_document_id_overwrite(case: dict[str, Any]) -> None:
    """Unauthorized replacement of an existing document cannot be committed.

    Mechanism-agnostic: it does not matter whether the control is a pre-check,
    a constrained DELETE or a lock, only that no destructive write commits,
    the caller is refused without detail, and one bounded event is emitted.
    """
    document_id = payload_of(case)
    # Control: with no existing document the same request is a normal ingest,
    # so a refusal below is caused by the existing document, not the harness.
    control = run_fake_db_ingest(document_id, existing=[])
    require(control.response.status_code == 200, "control ingest did not succeed")
    require(control.committed_writes, "control ingest committed no writes")

    existing = [
        {
            "tenant_id": "tenant-a",
            "document_id": document_id,
            "source": "restricted-incident.md",
            "chunk_index": 0,
            "content": "SYNTHETIC RESTRICTED MARKER",
            "classification": "restricted",
            "allowed_roles": ["admin"],
        }
    ]
    capture = run_fake_db_ingest(document_id, existing=existing)
    assert capture.response.status_code == 403
    assert not capture.committed_writes
    body = capture.response.text.lower()
    for leaked in ("restricted", "incident", "marker", "admin", document_id):
        assert leaked not in body, leaked
    assert capture.events == [{"event": "classification_denied", "role": "ingestor"}]


def run_header_role_assertion(case: dict[str, Any]) -> None:
    response, fake = run_generate(SELF_ASSERTED_ADMIN_A)
    assert response.status_code in {401, 403}
    fake.converse.assert_not_called()


def run_header_role_assertion_current(case: dict[str, Any]) -> None:
    response, fake = run_generate(SELF_ASSERTED_ADMIN_A)
    assert response.status_code == 200
    fake.converse.assert_called_once()


RUNNERS: dict[str, Callable[[dict[str, Any]], None]] = {
    "direct_structural": run_direct_structural,
    "restricted_action": run_restricted_action,
    "secret_extraction": run_secret_extraction,
    "question_boundary_direct": run_question_boundary_direct,
    "hidden_chars_question": run_hidden_chars_question,
    "passage_boundary": run_passage_boundary,
    "passage_boundary_current": run_passage_boundary_current,
    "question_boundary_chunk": run_question_boundary_chunk,
    "question_boundary_chunk_current": run_question_boundary_chunk_current,
    "hidden_chars_chunk": run_hidden_chars_chunk,
    "citation_index": run_citation_index,
    "citation_index_current": run_citation_index_current,
    "output_secret_leak": run_output_secret_leak,
    "no_tools": run_no_tools,
    "document_id_overwrite": run_document_id_overwrite,
    "header_role_assertion": run_header_role_assertion,
    "header_role_assertion_current": run_header_role_assertion_current,
}


# --- corpus integrity tripwires ----------------------------------------------


def test_corpus_schema_is_strict() -> None:
    assert CASES, "adversarial corpus is empty"
    ids = [case["id"] for case in CASES]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    for case in CASES:
        cid = case.get("id")
        assert set(case) == CASE_FIELDS, (cid, set(case) ^ CASE_FIELDS)
        assert case["category"] in CATEGORIES, (cid, case["category"])
        assert case["control_status"] in CONTROL_STATUSES, (cid, case["control_status"])
        assert case["source"] in SOURCES, (cid, case["source"])
        assert case["priority"] in PRIORITIES, (cid, case["priority"])
        assert (case["payload"] is None) or (case["payload_ref"] is None), cid
        if case["payload_ref"] is not None:
            assert case["payload_ref"] in PI_BY_ID, (cid, case["payload_ref"])
        assert all(ATLAS_ID.match(t) for t in case["atlas"]), (cid, case["atlas"])
        assert case["owasp"] and all(OWASP_ID.match(t) for t in case["owasp"]), cid
        assert case["expected_behavior"].strip(), cid


def test_every_case_has_a_runner() -> None:
    missing = {case["id"]: case["check"] for case in CASES if case["check"] not in RUNNERS}
    assert missing == {}, f"cases with no runner: {missing}"


def test_no_runner_is_dead() -> None:
    used = {case["check"] for case in CASES}
    assert set(RUNNERS) - used == set(), "runners not exercised by any case"


def test_every_existing_pi_case_is_executed() -> None:
    referenced = {case["payload_ref"] for case in CASES if case["payload_ref"]}
    assert referenced == set(PI_BY_ID), set(PI_BY_ID) ^ referenced


def test_characterization_cases_have_a_secure_counterpart() -> None:
    """Evidence of a gap must sit next to the strict-xfail invariant for it."""
    ids = {case["id"] for case in CASES}
    for case in CASES:
        if case["control_status"] == "characterization":
            assert case["id"].endswith("C"), case["id"]
            assert case["id"][:-1] in ids, case["id"]


# --- execution ---------------------------------------------------------------


def _param(case: dict[str, Any]) -> Any:
    marks = []
    if case["control_status"] == "not_implemented":
        marks.append(
            pytest.mark.xfail(
                strict=True,
                raises=AssertionError,
                reason=f"{case['id']}: control not implemented ({case['priority']})",
            )
        )
    return pytest.param(case, id=case["id"], marks=marks)


@pytest.mark.parametrize("case", [_param(case) for case in CASES])
def test_adversarial_case(case: dict[str, Any]) -> None:
    EXECUTED.add(case["id"])
    RUNNERS[case["check"]](case)


def test_every_collected_case_executed(request: pytest.FixtureRequest) -> None:
    """Corpus size and executed count must match whenever the full set runs."""
    collected = {
        item.callspec.id  # type: ignore[attr-defined]
        for item in request.session.items
        if item.originalname == "test_adversarial_case"  # type: ignore[attr-defined]
    }
    corpus = {case["id"] for case in CASES}
    if collected != corpus:
        pytest.skip("partial selection; full-corpus count is enforced by run_evaluations.py")
    assert EXECUTED == corpus, corpus - EXECUTED
