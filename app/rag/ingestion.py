"""Document ingestion: read -> chunk -> embed -> upsert, scoped to a tenant.

Milestone 6 moves this behind S3 -> SQS with a DLQ; the pipeline stages and
their contracts stay the same.
"""
import time
from pathlib import Path

from app.auth.permissions import Classification
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.telemetry import RAG_INGEST_CHUNKS, RAG_INGEST_DURATION, TRACER, record_error
from app.rag.chunking import chunk_text
from app.rag.embeddings import EmbeddingService
from app.rag.retrieval import VectorStore

logger = get_logger(__name__)


class IngestionService:
    def __init__(self, embeddings: EmbeddingService, store: VectorStore) -> None:
        self._embeddings = embeddings
        self._store = store
        self._settings = get_settings()

    def ingest_text(
        self,
        tenant_id: str,
        source: str,
        classification: Classification,
        text: str,
        document_id: str | None = None,
        allowed_roles: list[str] | None = None,
    ) -> int:
        started = time.perf_counter()
        attributes = {"classification": classification.value}
        with TRACER.start_as_current_span("rag.ingest") as span:
            span.set_attribute("classification", classification.value)
            try:
                chunks = chunk_text(
                    text,
                    max_chars=self._settings.chunk_max_chars,
                    overlap_chars=self._settings.chunk_overlap_chars,
                )
                rows: list[tuple[int, str, list[float]]] = []
                for chunk in chunks:
                    rows.append((chunk.index, chunk.text, self._embeddings.embed(chunk.text)))
                count = self._store.upsert_chunks(
                    tenant_id,
                    source,
                    classification,
                    rows,
                    document_id=document_id,
                    allowed_roles=allowed_roles,
                )
                span.set_attribute("chunk_count", count)
                span.set_attribute("outcome", "success")
                RAG_INGEST_CHUNKS.record(
                    count, {**attributes, "outcome": "success"}
                )
                logger.info(
                    "document_ingested",
                    source=source,
                    classification=classification.value,
                    chunks=count,
                )
                return count
            except Exception as exc:
                error_type = record_error(span, exc)
                span.set_attribute("outcome", "error")
                attributes["error.type"] = error_type
                RAG_INGEST_CHUNKS.record(0, {**attributes, "outcome": "error"})
                raise
            finally:
                RAG_INGEST_DURATION.record(
                    time.perf_counter() - started,
                    {**attributes, "outcome": "error" if "error.type" in attributes else "success"},
                )

    def ingest_file(
        self,
        path: Path,
        tenant_id: str,
        classification: Classification,
        source: str | None = None,
        document_id: str | None = None,
        allowed_roles: list[str] | None = None,
    ) -> int:
        return self.ingest_text(
            tenant_id=tenant_id,
            source=source or path.name,
            classification=classification,
            text=path.read_text(encoding="utf-8"),
            document_id=document_id,
            allowed_roles=allowed_roles,
        )
