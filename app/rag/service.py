"""RAG orchestration: authorize -> retrieve -> ground -> generate -> cite."""
import time

from app.auth.tenancy import TenantContext
from app.clients.bedrock import BedrockService
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.telemetry import (
    RAG_QUERY_DURATION,
    RAG_QUERY_RETRIEVED_CHUNKS,
    TRACER,
    record_error,
)
from app.models.responses import Citation, QueryResponse
from app.rag.embeddings import EmbeddingService
from app.rag.output_integrity import review_answer
from app.rag.prompting import SYSTEM_PROMPT, QuestionTooLargeError, frame_user_prompt
from app.rag.retrieval import VectorStore

logger = get_logger(__name__)

NO_CONTEXT_ANSWER = (
    "I cannot answer that from the available documents. "
    "The knowledge base has no relevant content for this question."
)


class RagService:
    def __init__(
        self,
        bedrock: BedrockService,
        embeddings: EmbeddingService,
        store: VectorStore,
    ) -> None:
        self._bedrock = bedrock
        self._embeddings = embeddings
        self._store = store
        self._settings = get_settings()

    def query(
        self, question: str, context: TenantContext, top_k: int | None = None
    ) -> QueryResponse:
        started = time.perf_counter()
        attributes = {"role": context.role.value}
        outcome = "error"
        error_type: str | None = None
        with TRACER.start_as_current_span("rag.query") as span:
            span.set_attribute("role", context.role.value)
            try:
                # The caller's own input is the only size limit attributed to
                # the caller; checked before any embedding or retrieval cost.
                if len(question) > self._settings.max_question_chars:
                    raise QuestionTooLargeError(
                        f"Question of {len(question)} chars exceeds limit of "
                        f"{self._settings.max_question_chars}"
                    )
                embedding = self._embeddings.embed(question)
                chunks = self._store.search(embedding, context=context, top_k=top_k)
                result_count = len(chunks)
                span.set_attribute("result_count", result_count)
                framed = (
                    frame_user_prompt(
                        question, chunks, budget=self._settings.max_input_chars
                    )
                    if chunks
                    else None
                )
                if framed is None or not framed.included:
                    # Authorized-but-empty and unauthorized are indistinguishable;
                    # context that cannot fit the budget is refused the same way.
                    logger.info("query_no_context", retrieved=result_count)
                    outcome = "no_context"
                    span.set_attribute("outcome", outcome)
                    RAG_QUERY_RETRIEVED_CHUNKS.record(0, {**attributes, "outcome": "no_context"})
                    return QueryResponse(
                        request_id="",
                        answer=NO_CONTEXT_ANSWER,
                        citations=[],
                        model_id=self._settings.bedrock_model_id,
                        input_tokens=0,
                        output_tokens=0,
                        latency_ms=0,
                    )

                result = self._bedrock.invoke(framed.text, system=SYSTEM_PROMPT)
                # Output checks run before anything from the answer is used.
                reviewed = review_answer(result.text, len(framed.included))
                # Cite only passages the answer validly cites; never substitute.
                citations = [
                    Citation(
                        index=i,
                        source=framed.included[i - 1].source,
                        chunk_index=framed.included[i - 1].chunk_index,
                        score=round(framed.included[i - 1].score, 4),
                    )
                    for i in reviewed.cited
                ]
                if reviewed.withheld is not None:
                    # Bounded reason only; the model text is never logged here.
                    logger.info(
                        "query_answer_withheld",
                        role=context.role.value,
                        reason=reviewed.withheld.value,
                        request_id=result.request_id,
                    )
                else:
                    logger.info(
                        "query_answered",
                        role=context.role.value,
                        retrieved=result_count,
                        request_id=result.request_id,
                    )
                outcome = "answered"
                span.set_attribute("outcome", outcome)
                RAG_QUERY_RETRIEVED_CHUNKS.record(
                    result_count, {**attributes, "outcome": "answered"}
                )
                return QueryResponse(
                    request_id=result.request_id,
                    answer=reviewed.answer,
                    citations=citations,
                    model_id=result.model_id,
                    input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens,
                    latency_ms=result.latency_ms,
                )
            except Exception as exc:
                error_type = record_error(span, exc)
                span.set_attribute("outcome", "error")
                RAG_QUERY_RETRIEVED_CHUNKS.record(
                    0, {**attributes, "outcome": "error", "error.type": error_type}
                )
                raise
            finally:
                RAG_QUERY_DURATION.record(
                    time.perf_counter() - started,
                    {
                        **attributes,
                        "outcome": outcome,
                        **({"error.type": error_type} if error_type else {}),
                    },
                )
