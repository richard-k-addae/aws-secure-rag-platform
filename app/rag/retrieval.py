"""pgvector-backed retrieval with tenant isolation.

Chunks carry tenant_id, document_id, classification, allowed_roles and
source. Authorization uses two complementary controls: classification is the
coarse sensitivity tier a role may read, and allowed_roles is an optional
per-document ACL that narrows access further (empty = governed by
classification alone). A caller must satisfy both.

Schema creation and role provisioning live in app/rag/schema.py and run under
an administrative connection; this module only ever uses the runtime role,
which is provisioned NOSUPERUSER NOBYPASSRLS so row-level security applies to
it.

Two independent layers enforce isolation (ADR 0002):

1. Application layer - every query filters on tenant_id and the caller's
   allowed classifications inside the SQL WHERE clause, so unauthorized
   chunks are never fetched into application memory.
2. Database layer - PostgreSQL row-level security, FORCEd so it applies to
   the table owner, with a runtime role provisioned NOBYPASSRLS. Each
   connection sets `app.tenant_id` via
   set_config(); when it is unset the policy matches nothing, so a coding
   mistake fails closed rather than leaking rows.

Vectors and identifiers are always passed as query parameters - no SQL is
built from caller-controlled strings.
"""
import time
from dataclasses import dataclass
from typing import Any

import psycopg

from app.auth.permissions import Classification
from app.auth.tenancy import TenantContext
from app.core.config import get_settings
from app.core.telemetry import (
    DB_OPERATION_DURATION,
    RAG_RETRIEVAL_DURATION,
    RAG_RETRIEVAL_RESULTS,
    TRACER,
    record_error,
    record_security_event,
)


@dataclass(frozen=True)
class RetrievedChunk:
    source: str
    chunk_index: int
    content: str
    score: float
    document_id: str = ""
    tenant_id: str = ""


class DocumentReplacementDeniedError(PermissionError):
    """The caller may not replace an existing document it is not authorized for.

    Carries no detail about the existing document, so it cannot leak its
    classification, source, content or access list.
    """


class DocumentReplacementConflictError(RuntimeError):
    """The document changed between authorization and deletion; nothing is kept."""


def _vector_literal(embedding: list[float]) -> str:
    return "[" + ",".join(f"{x:.8f}" for x in embedding) + "]"


def _may_access(context: TenantContext, classification: str, allowed_roles: list[str]) -> bool:
    """Same rule as search(): classification clearance AND the per-document ACL."""
    cleared = {c.value for c in context.allowed_classifications}
    return classification in cleared and (not allowed_roles or context.role.value in allowed_roles)


class VectorStore:
    def __init__(self, conninfo: str | None = None) -> None:
        settings = get_settings()
        self._conninfo = conninfo or settings.database_url
        self._settings = settings

    def _connect(self) -> psycopg.Connection[Any]:
        return psycopg.connect(self._conninfo)

    def _connect_as(self, tenant_id: str) -> psycopg.Connection[Any]:
        """Open a connection scoped to a tenant for the current transaction."""
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))
        return conn

    def upsert_chunks(
        self,
        tenant_id: str,
        source: str,
        classification: Classification,
        chunks: list[tuple[int, str, list[float]]],
        document_id: str | None = None,
        allowed_roles: list[str] | None = None,
        *,
        authorize_as: TenantContext | None,
    ) -> int:
        """Replace a document's chunks. allowed_roles=[] means classification governs.

        ``authorize_as`` is required and has no default: every caller must
        choose. Pass the resolved caller to authorize the EXISTING document
        before anything is deleted: the caller must be able to access every
        existing chunk under that chunk's own classification and ACL (the
        incoming classification can never lower the bar). The check, delete
        and insert share one transaction, so a rejection leaves no partial
        state. ``authorize_as=None`` is an explicit, privileged operator path
        (setup scripts, tests) that skips the check; it is never selected by
        omission, and API routes must always pass the caller.
        """
        started = time.perf_counter()
        attributes = {"operation": "upsert"}
        with TRACER.start_as_current_span("rag.ingest.upsert") as span:
            span.set_attribute("operation", "upsert")
            try:
                doc_id = document_id or source
                roles = allowed_roles or []
                if authorize_as is not None and authorize_as.tenant_id != tenant_id:
                    raise DocumentReplacementDeniedError("not authorized to replace this document")
                with self._connect_as(tenant_id) as conn, conn.cursor() as cur:
                    if authorize_as is None:
                        cur.execute(
                            "DELETE FROM document_chunks "
                            "WHERE tenant_id = %s AND document_id = %s",
                            (tenant_id, doc_id),
                        )
                    else:
                        self._authorize_and_delete(cur, tenant_id, doc_id, authorize_as)
                    for index, content, embedding in chunks:
                        cur.execute(
                            "INSERT INTO document_chunks "
                            "(tenant_id, document_id, source, chunk_index, content, "
                            "classification, allowed_roles, embedding) "
                            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s::vector)",
                            (
                                tenant_id,
                                doc_id,
                                source,
                                index,
                                content,
                                classification.value,
                                roles,
                                _vector_literal(embedding),
                            ),
                        )
                span.set_attribute("outcome", "success")
                return len(chunks)
            except Exception as exc:
                error_type = record_error(span, exc)
                if error_type == "InsufficientPrivilege":
                    record_security_event("rls_violation")
                span.set_attribute("outcome", "error")
                attributes["error.type"] = error_type
                raise
            finally:
                DB_OPERATION_DURATION.record(
                    time.perf_counter() - started,
                    {**attributes, "outcome": "error" if "error.type" in attributes else "success"},
                )

    @staticmethod
    def _authorize_and_delete(
        cur: psycopg.Cursor[Any], tenant_id: str, doc_id: str, context: TenantContext
    ) -> None:
        """Authorize against the existing document, then delete exactly what was authorized.

        1. A transaction-scoped advisory lock serializes writers of this
           (tenant, document_id), closing the window in which a concurrent
           writer could insert rows after the check (a lock on existing rows
           alone cannot cover rows that do not exist yet).
        2. Existing chunks are read FOR UPDATE and authorized as a whole:
           one inaccessible chunk denies the entire replacement.
        3. Defense in depth: the DELETE repeats the access predicate, and the
           deleted count must equal the authorized count or the transaction
           is aborted, so a partial delete can never be committed.
        """
        cur.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            # A key collision only adds serialization; it never grants access.
            (f"document_chunks|{tenant_id}|{doc_id}",),
        )
        cur.execute(
            "SELECT classification, allowed_roles FROM document_chunks "
            "WHERE tenant_id = %s AND document_id = %s FOR UPDATE",
            (tenant_id, doc_id),
        )
        existing = cur.fetchall()
        if not all(_may_access(context, row[0], list(row[1] or [])) for row in existing):
            raise DocumentReplacementDeniedError("not authorized to replace this document")
        cur.execute(
            "DELETE FROM document_chunks "
            "WHERE tenant_id = %s AND document_id = %s "
            "AND classification = ANY(%s) "
            "AND (cardinality(allowed_roles) = 0 OR %s = ANY(allowed_roles))",
            (
                tenant_id,
                doc_id,
                sorted(c.value for c in context.allowed_classifications),
                context.role.value,
            ),
        )
        if cur.rowcount != len(existing):
            raise DocumentReplacementConflictError("document changed during replacement")

    def search(
        self,
        embedding: list[float],
        context: TenantContext,
        top_k: int | None = None,
        min_score: float | None = None,
    ) -> list[RetrievedChunk]:
        """Return chunks for this tenant that the caller's role may read."""
        started = time.perf_counter()
        attributes = {"operation": "search"}
        outcome = "error"
        with TRACER.start_as_current_span("rag.retrieval.search") as span:
            span.set_attribute("operation", "search")
            try:
                k = top_k or self._settings.retrieval_top_k
                threshold = (
                    min_score if min_score is not None else self._settings.retrieval_min_score
                )
                classifications = sorted(c.value for c in context.allowed_classifications)
                if not classifications:
                    results: list[RetrievedChunk] = []
                else:
                    vector = _vector_literal(embedding)
                    with self._connect_as(context.tenant_id) as conn, conn.cursor() as cur:
                        cur.execute(
                            "SELECT source, chunk_index, content, document_id, tenant_id, "
                            "1 - (embedding <=> %s::vector) AS score "
                            "FROM document_chunks "
                            "WHERE tenant_id = %s AND classification = ANY(%s) "
                            "AND (cardinality(allowed_roles) = 0 OR %s = ANY(allowed_roles)) "
                            "ORDER BY embedding <=> %s::vector "
                            "LIMIT %s",
                            (
                                vector,
                                context.tenant_id,
                                classifications,
                                context.role.value,
                                vector,
                                k,
                            ),
                        )
                        rows = cur.fetchall()
                    results = [
                        RetrievedChunk(
                            source=r[0],
                            chunk_index=r[1],
                            content=r[2],
                            document_id=r[3],
                            tenant_id=r[4],
                            score=float(r[5]),
                        )
                        for r in rows
                        if float(r[5]) >= threshold
                    ]
                outcome = "hit" if results else "empty"
                span.set_attribute("outcome", outcome)
                span.set_attribute("result_count", len(results))
                RAG_RETRIEVAL_RESULTS.record(len(results), {**attributes, "outcome": outcome})
                return results
            except Exception as exc:
                error_type = record_error(span, exc)
                if error_type == "InsufficientPrivilege":
                    record_security_event("rls_violation", role=context.role.value)
                span.set_attribute("outcome", "error")
                attributes["error.type"] = error_type
                RAG_RETRIEVAL_RESULTS.record(0, {**attributes, "outcome": "error"})
                raise
            finally:
                elapsed = time.perf_counter() - started
                metric_attributes = {**attributes, "outcome": outcome}
                RAG_RETRIEVAL_DURATION.record(elapsed, metric_attributes)
                DB_OPERATION_DURATION.record(elapsed, metric_attributes)
