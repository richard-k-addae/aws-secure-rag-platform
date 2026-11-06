"""Database-level isolation: PostgreSQL row-level security.

These run against a real PostgreSQL + pgvector instance and use two roles,
mirroring production:

* ``TEST_ADMIN_DATABASE_URL`` - superuser. Creates the extension, table,
  policy and the runtime role. DDL only.
* ``TEST_DATABASE_URL`` - the runtime role, provisioned NOSUPERUSER
  NOBYPASSRLS. Every isolation assertion below runs as this role.

The distinction is the whole point. PostgreSQL exempts superusers and
BYPASSRLS roles from row-level security unconditionally, and FORCE ROW LEVEL
SECURITY removes only the table-owner exemption. Connecting as a superuser
therefore disables row security silently while every application-layer test
still passes (docs/security/FINDINGS.md, F-001).

Both variables must be set; otherwise these tests skip and the row-security
layer is unproven.
"""
import os
from collections.abc import Iterator
from typing import Any

import pytest

from app.tests.conftest import (
    ADMIN_A_HEADERS,
    INGESTOR_A_HEADERS,
    INGESTOR_B_HEADERS,
    TENANT_A_HEADERS,
    TENANT_B_HEADERS,
)
from app.tests.identity import TEST_KID, claims, new_key, sign

psycopg = pytest.importorskip("psycopg")
sql = psycopg.sql

ADMIN_URL = os.environ.get("TEST_ADMIN_DATABASE_URL")
APP_URL = os.environ.get("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not (ADMIN_URL and APP_URL),
    reason=(
        "TEST_ADMIN_DATABASE_URL and TEST_DATABASE_URL must both be set; "
        "row-security tests run in the CI integration job"
    ),
)

DIMS = 4
APP_ROLE = os.environ.get("TEST_APP_ROLE", "rag_app")
APP_PASSWORD = os.environ.get("TEST_APP_PASSWORD", "rag_app")
# For roles these tests create and drop themselves; never a real credential.
THROWAWAY_PASSWORD = os.environ.get("TEST_THROWAWAY_PASSWORD", "throwaway-test-only")


def vec(values: list[float]) -> str:
    return "[" + ",".join(str(v) for v in values) + "]"


def app_connect() -> Any:
    """Connect as the runtime (non-superuser, NOBYPASSRLS) role."""
    return psycopg.connect(APP_URL or "")


@pytest.fixture()
def store() -> Iterator[Any]:
    """Provision schema as admin, then hand back a runtime-role store."""
    from app.rag.retrieval import VectorStore
    from app.rag.schema import initialize_schema

    initialize_schema(
        ADMIN_URL or "",
        dimensions=DIMS,
        app_role=APP_ROLE,
        app_password=APP_PASSWORD,
    )

    st = VectorStore(conninfo=APP_URL or "")
    # Clean per tenant: as the runtime role, RLS scopes DELETE to the session
    # tenant, so each tenant must be cleared under its own context.
    for tenant in ("tenant-a", "tenant-b"):
        with app_connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))
            cur.execute("DELETE FROM document_chunks")

    from app.auth.permissions import Classification

    st.upsert_chunks(
        "tenant-a",
        "a.md",
        Classification.INTERNAL,
        [(0, "tenant A secret", [1.0, 0, 0, 0])],
        document_id="doc-a",
        authorize_as=None,
    )
    st.upsert_chunks(
        "tenant-b",
        "b.md",
        Classification.INTERNAL,
        [(0, "tenant B secret", [1.0, 0, 0, 0])],
        document_id="doc-b",
        authorize_as=None,
    )
    yield st


# --- the precondition that makes every test below meaningful ---------------


def test_runtime_role_cannot_bypass_row_security() -> None:
    """Without this, row-level security is silently inert (F-001)."""
    from app.rag.schema import assert_no_rls_bypass

    rolsuper, rolbypassrls = assert_no_rls_bypass(APP_URL or "")
    assert rolsuper is False, "runtime role must not be a superuser"
    assert rolbypassrls is False, "runtime role must not hold BYPASSRLS"


def test_runtime_role_is_not_the_table_owner() -> None:
    with app_connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT tableowner <> current_user FROM pg_tables WHERE tablename = %s",
            ("document_chunks",),
        )
        row = cur.fetchone()
    assert row is not None
    assert row[0] is True


# --- bootstrap is safe to re-run and fails closed ----------------------------


def _role_attributes(role: str) -> tuple[bool, bool, bool, bool] | None:
    with psycopg.connect(ADMIN_URL or "") as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole "
            "FROM pg_roles WHERE rolname = %s",
            (role,),
        )
        row = cur.fetchone()
    return None if row is None else (bool(row[0]), bool(row[1]), bool(row[2]), bool(row[3]))


def test_initialize_schema_is_safe_to_rerun() -> None:
    from app.rag.schema import initialize_schema

    for _ in range(2):
        initialize_schema(
            ADMIN_URL or "", dimensions=DIMS, app_role=APP_ROLE, app_password=APP_PASSWORD
        )

    assert _role_attributes(APP_ROLE) == (False, False, False, False)
    with psycopg.connect(ADMIN_URL or "") as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = %s",
            ("document_chunks",),
        )
        assert cur.fetchone() == (True, True)


def test_initialize_schema_rejects_overprivileged_runtime_role() -> None:
    """An existing role that could escape row security gets no grant at all."""
    from app.rag.schema import RuntimeRoleOverprivilegedError, initialize_schema

    role = "rag_overprivileged_test"
    with psycopg.connect(ADMIN_URL or "", autocommit=True) as conn:
        conn.execute(f"DROP ROLE IF EXISTS {role}")
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} BYPASSRLS").format(
                sql.Identifier(role), sql.Literal(THROWAWAY_PASSWORD)
            )
        )
    try:
        with pytest.raises(RuntimeRoleOverprivilegedError, match="rolbypassrls"):
            initialize_schema(
                ADMIN_URL or "", dimensions=DIMS, app_role=role, app_password=THROWAWAY_PASSWORD
            )
        with psycopg.connect(ADMIN_URL or "") as conn, conn.cursor() as cur:
            cur.execute("SELECT has_table_privilege(%s, 'document_chunks', 'SELECT')", (role,))
            row = cur.fetchone()
        assert row is not None
        assert row[0] is False
        # Validated, not silently repaired.
        assert _role_attributes(role) == (False, True, False, False)
    finally:
        with psycopg.connect(ADMIN_URL or "", autocommit=True) as conn:
            conn.execute(f"DROP ROLE IF EXISTS {role}")


def test_bootstrap_reruns_under_a_non_superuser_admin() -> None:
    """Mirrors Amazon RDS, where the master user is not a PostgreSQL superuser.

    A second run must not need superuser-only statements such as
    ALTER ROLE ... NOSUPERUSER.

    The extension is installed by the superuser first: RDS lets its master
    user create pgvector, stock PostgreSQL does not, and that one difference
    is not what this test is about.
    """
    from psycopg.conninfo import make_conninfo

    from app.rag.schema import initialize_schema

    admin, runtime, database = "rag_rdslike_admin", "rag_rdslike_app", "rag_rdslike_test"

    def drop_all() -> None:
        with psycopg.connect(ADMIN_URL or "", autocommit=True) as conn:
            conn.execute(f"DROP DATABASE IF EXISTS {database} WITH (FORCE)")
            conn.execute(f"DROP ROLE IF EXISTS {runtime}")
            conn.execute(f"DROP ROLE IF EXISTS {admin}")

    drop_all()
    with psycopg.connect(ADMIN_URL or "", autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER CREATEROLE CREATEDB").format(
                sql.Identifier(admin), sql.Literal(THROWAWAY_PASSWORD)
            )
        )
        conn.execute(f"CREATE DATABASE {database} OWNER {admin}")
    try:
        with psycopg.connect(
            make_conninfo(ADMIN_URL or "", dbname=database), autocommit=True
        ) as conn:
            conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        admin_conninfo = make_conninfo(
            ADMIN_URL or "", user=admin, password=THROWAWAY_PASSWORD, dbname=database
        )
        for _ in range(2):
            initialize_schema(
                admin_conninfo,
                dimensions=DIMS,
                app_role=runtime,
                app_password=THROWAWAY_PASSWORD,
            )
        assert _role_attributes(runtime) == (False, False, False, False)
    finally:
        drop_all()


# --- application-layer filtering -------------------------------------------


def test_search_returns_only_own_tenant_rows(store: Any) -> None:
    from app.auth.permissions import Role, allowed_classifications
    from app.auth.tenancy import TenantContext

    ctx = TenantContext(
        tenant_id="tenant-a",
        role=Role.READER,
        allowed_classifications=allowed_classifications(Role.READER),
    )
    results = store.search([1.0, 0, 0, 0], context=ctx)
    assert [r.content for r in results] == ["tenant A secret"]


def test_identical_similarity_across_tenants_returns_only_own_rows(store: Any) -> None:
    """Both tenants hold an identical vector; tenant A must still see only its own."""
    from app.auth.permissions import Role, allowed_classifications
    from app.auth.tenancy import TenantContext

    ctx = TenantContext(
        tenant_id="tenant-a",
        role=Role.READER,
        allowed_classifications=allowed_classifications(Role.READER),
    )
    results = store.search([1.0, 0, 0, 0], context=ctx, top_k=10)
    assert results
    assert all(r.tenant_id == "tenant-a" for r in results)
    assert not any("tenant B" in r.content for r in results)


def test_document_acl_excludes_roles_not_listed(store: Any) -> None:
    from app.auth.permissions import Classification, Role, allowed_classifications
    from app.auth.tenancy import TenantContext

    store.upsert_chunks(
        "tenant-a",
        "admin-only.md",
        Classification.INTERNAL,
        [(0, "admin eyes only", [1.0, 0, 0, 0])],
        document_id="doc-admin",
        allowed_roles=["admin"],
        authorize_as=None,
    )
    reader_ctx = TenantContext(
        tenant_id="tenant-a",
        role=Role.READER,
        allowed_classifications=allowed_classifications(Role.READER),
    )
    admin_ctx = TenantContext(
        tenant_id="tenant-a",
        role=Role.ADMIN,
        allowed_classifications=allowed_classifications(Role.ADMIN),
    )
    reader = store.search([1.0, 0, 0, 0], context=reader_ctx, top_k=10)
    admin = store.search([1.0, 0, 0, 0], context=admin_ctx, top_k=10)
    assert not any(r.document_id == "doc-admin" for r in reader)
    assert any(r.document_id == "doc-admin" for r in admin)


# --- database-layer enforcement, independent of application code -----------


def test_rls_blocks_unfiltered_query(store: Any) -> None:
    """A query with NO tenant predicate still returns only the session tenant."""
    with app_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', 'tenant-a', true)")
        cur.execute("SELECT content FROM document_chunks")
        rows = [r[0] for r in cur.fetchall()]
    assert rows == ["tenant A secret"]


def test_rls_returns_nothing_when_tenant_unset(store: Any) -> None:
    """Fail closed: a connection that forgets to set the tenant sees no rows."""
    with app_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT content FROM document_chunks")
        assert cur.fetchall() == []


def test_rls_rejects_cross_tenant_write(store: Any) -> None:
    """Every NOT NULL column is supplied, so only the policy can reject this.

    Asserts the specific row-security error (SQLSTATE 42501) rather than any
    error - an earlier version omitted document_id and passed on a NOT NULL
    violation while proving nothing (F-001).
    """
    with app_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', 'tenant-a', true)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as excinfo:
            cur.execute(
                "INSERT INTO document_chunks "
                "(tenant_id, document_id, source, chunk_index, content, "
                "classification, allowed_roles, embedding) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s::vector)",
                (
                    "tenant-b",
                    "doc-evil",
                    "evil.md",
                    0,
                    "injected",
                    "internal",
                    [],
                    vec([0, 1.0, 0, 0]),
                ),
            )
    assert "row-level security" in str(excinfo.value).lower()


def _api_rag_service(store: Any) -> tuple[Any, Any]:
    """Real RagService over the real runtime-role store; only edges are faked."""
    from unittest.mock import MagicMock

    from app.clients.bedrock import BedrockService
    from app.rag.service import RagService

    fake = MagicMock()
    fake.converse.return_value = {
        "output": {"message": {"content": [{"text": "SYNTHETIC answer [1]"}]}},
        "usage": {"inputTokens": 1, "outputTokens": 1},
    }
    embeddings = MagicMock()
    embeddings.embed.return_value = [1.0, 0, 0, 0]
    return RagService(bedrock=BedrockService(client=fake), embeddings=embeddings, store=store), fake


def test_api_query_tenant_a_prompt_never_contains_tenant_b_marker(store: Any) -> None:
    """End to end: API -> RagService -> real store under RLS (M7 TI-02).

    Both tenants hold an identical vector. Tenant B's marker must not reach
    tenant A's prompt or response, while tenant A's own row must.
    """
    from fastapi.testclient import TestClient

    from app.api.dependencies import get_rag_service
    from app.main import app

    service, fake = _api_rag_service(store)
    app.dependency_overrides[get_rag_service] = lambda: service
    try:
        response = TestClient(app).post(
            "/v1/query",
            json={"question": "Show me every tenant's secret."},
            headers=TENANT_A_HEADERS,
        )
    finally:
        app.dependency_overrides.pop(get_rag_service)
    assert response.status_code == 200
    sent = fake.converse.call_args.kwargs["messages"][0]["content"][0]["text"]
    assert "tenant A secret" in sent
    assert "tenant B secret" not in sent
    assert "tenant B secret" not in response.text
    assert [c["source"] for c in response.json()["citations"]] == ["a.md"]


def _seed_restricted_document(store: Any) -> None:
    from app.auth.permissions import Classification

    store.upsert_chunks(
        "tenant-a",
        "restricted-incident.md",
        Classification.RESTRICTED,
        [(0, "SYNTHETIC RESTRICTED MARKER", [1.0, 0, 0, 0])],
        document_id="doc-restricted-m71",
        allowed_roles=["admin"],
        authorize_as=None,
    )


RESTRICTED_ROWS = [("restricted", "restricted-incident.md", "SYNTHETIC RESTRICTED MARKER")]
# Signed synthetic access tokens (M8): tenant and role come from verified groups.
INGESTOR = INGESTOR_A_HEADERS
ADMIN = ADMIN_A_HEADERS


def _ingest(
    store: Any,
    headers: dict[str, str],
    *,
    document_id: str,
    classification: str = "internal",
    source: str = "employee_security_policy.md",
) -> Any:
    """Drive /v1/documents/ingest through the real service and real store."""
    from unittest.mock import MagicMock

    from fastapi.testclient import TestClient

    from app.api.dependencies import get_ingestion_service
    from app.main import app
    from app.rag.ingestion import IngestionService

    embeddings = MagicMock()
    embeddings.embed.return_value = [1.0, 0, 0, 0]
    service = IngestionService(embeddings=embeddings, store=store)
    app.dependency_overrides[get_ingestion_service] = lambda: service
    try:
        return TestClient(app).post(
            "/v1/documents/ingest",
            json={"source": source, "classification": classification, "document_id": document_id},
            headers=headers,
        )
    finally:
        app.dependency_overrides.pop(get_ingestion_service)


def _document_rows(
    document_id: str, tenant: str = "tenant-a"
) -> list[tuple[str, str, str]]:
    with app_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))
        cur.execute(
            "SELECT classification, source, content FROM document_chunks "
            "WHERE document_id = %s ORDER BY chunk_index",
            (document_id,),
        )
        return [(r[0], r[1], r[2]) for r in cur.fetchall()]


def _tenant_snapshot(tenant: str = "tenant-a") -> list[tuple[Any, ...]]:
    """Every column of every row in a tenant, for exact before/after comparison."""
    with app_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))
        cur.execute(
            "SELECT id, document_id, source, chunk_index, content, classification, "
            "allowed_roles, embedding::text, created_at FROM document_chunks ORDER BY id"
        )
        return [tuple(r) for r in cur.fetchall()]


def _insert_raw_chunk(
    document_id: str, source: str, index: int, content: str, classification: str
) -> None:
    with app_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', 'tenant-a', true)")
        cur.execute(
            "INSERT INTO document_chunks (tenant_id, document_id, source, chunk_index, "
            "content, classification, allowed_roles, embedding) "
            "VALUES ('tenant-a', %s, %s, %s, %s, %s, '{}', %s::vector)",
            (document_id, source, index, content, classification, vec([1.0, 0, 0, 0])),
        )


def _capture_security_events(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    from app.core import telemetry

    events: list[dict[str, str]] = []
    monkeypatch.setattr(
        telemetry.SECURITY_EVENTS, "add", lambda value, attrs: events.append(dict(attrs))
    )
    return events


# --- M7.4a AUTHZ-01: replacing a document requires access to the EXISTING one --


@pytest.mark.parametrize("incoming", ["public", "internal", "confidential"])
def test_ingestor_cannot_overwrite_restricted_document_by_id(
    store: Any, incoming: str
) -> None:
    """The incoming classification can never lower the bar set by the existing one."""
    _seed_restricted_document(store)
    response = _ingest(store, INGESTOR, document_id="doc-restricted-m71", classification=incoming)
    assert response.status_code == 403
    assert _document_rows("doc-restricted-m71") == RESTRICTED_ROWS


def test_rejected_overwrite_is_atomic_leaks_nothing_and_emits_one_event(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No partial state, no existence detail in the body, exactly one bounded event."""
    _seed_restricted_document(store)
    before = _tenant_snapshot()
    events = _capture_security_events(monkeypatch)

    response = _ingest(store, INGESTOR, document_id="doc-restricted-m71")

    assert response.status_code == 403
    assert _tenant_snapshot() == before
    assert not any(row[2] == "employee_security_policy.md" for row in _tenant_snapshot())
    body = response.text.lower()
    for leaked in ("restricted", "incident", "marker", "admin", "doc-restricted"):
        assert leaked not in body, leaked
    assert events == [{"event": "classification_denied", "role": "ingestor"}]


def test_store_refuses_unauthorized_replacement_directly(store: Any) -> None:
    """The control lives in the store's transaction, not only in the route."""
    from app.auth.permissions import Classification, Role, allowed_classifications
    from app.auth.tenancy import TenantContext
    from app.rag.retrieval import DocumentReplacementDeniedError

    _seed_restricted_document(store)
    ingestor = TenantContext(
        tenant_id="tenant-a",
        role=Role.INGESTOR,
        allowed_classifications=allowed_classifications(Role.INGESTOR),
    )
    with pytest.raises(DocumentReplacementDeniedError):
        store.upsert_chunks(
            "tenant-a",
            "employee_security_policy.md",
            Classification.INTERNAL,
            [(0, "replacement", [1.0, 0, 0, 0])],
            document_id="doc-restricted-m71",
            authorize_as=ingestor,
        )
    other_tenant = TenantContext(
        tenant_id="tenant-b",
        role=Role.ADMIN,
        allowed_classifications=allowed_classifications(Role.ADMIN),
    )
    with pytest.raises(DocumentReplacementDeniedError):
        store.upsert_chunks(
            "tenant-a",
            "employee_security_policy.md",
            Classification.INTERNAL,
            [(0, "replacement", [1.0, 0, 0, 0])],
            document_id="doc-restricted-m71",
            authorize_as=other_tenant,
        )
    assert _document_rows("doc-restricted-m71") == RESTRICTED_ROWS


def test_concurrent_restricted_writer_is_serialized_before_authorization(store: Any) -> None:
    """White-box race test for the check -> delete window.

    A concurrent writer holds the per-document lock and has an uncommitted
    RESTRICTED row for the same document_id. The ingestor's replacement must
    wait, then authorize against the committed state and be denied, rather
    than authorizing against a stale empty read.
    """
    import threading
    import time as _time

    from app.auth.permissions import Classification, Role, allowed_classifications
    from app.auth.tenancy import TenantContext
    from app.rag.retrieval import DocumentReplacementDeniedError

    ingestor = TenantContext(
        tenant_id="tenant-a",
        role=Role.INGESTOR,
        allowed_classifications=allowed_classifications(Role.INGESTOR),
    )
    outcome: dict[str, BaseException | None] = {}

    def replace() -> None:
        try:
            store.upsert_chunks(
                "tenant-a",
                "employee_security_policy.md",
                Classification.INTERNAL,
                [(0, "replacement", [1.0, 0, 0, 0])],
                document_id="doc-race-m74",
                authorize_as=ingestor,
            )
            outcome["error"] = None
        except BaseException as exc:  # recorded for the assertion below
            outcome["error"] = exc

    with app_connect() as writer, writer.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', 'tenant-a', true)")
        cur.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            ("document_chunks|tenant-a|doc-race-m74",),
        )
        cur.execute(
            "INSERT INTO document_chunks (tenant_id, document_id, source, chunk_index, "
            "content, classification, allowed_roles, embedding) "
            "VALUES ('tenant-a', 'doc-race-m74', 'race.md', 0, 'SYNTHETIC RACE MARKER', "
            "'restricted', '{}', %s::vector)",
            (vec([1.0, 0, 0, 0]),),
        )
        worker = threading.Thread(target=replace)
        worker.start()
        _time.sleep(0.5)
        assert worker.is_alive(), "replacement did not wait for the concurrent writer"
    # Leaving the block commits the writer and releases its lock.
    worker.join(timeout=10)
    assert not worker.is_alive()
    assert isinstance(outcome["error"], DocumentReplacementDeniedError)
    assert _document_rows("doc-race-m74") == [("restricted", "race.md", "SYNTHETIC RACE MARKER")]


def test_document_acl_excluding_caller_blocks_replacement(store: Any) -> None:
    """An INTERNAL document the ingestor is cleared for, but whose ACL names only admin."""
    from app.auth.permissions import Classification

    store.upsert_chunks(
        "tenant-a",
        "admin-acl.md",
        Classification.INTERNAL,
        [(0, "SYNTHETIC ADMIN ACL MARKER", [1.0, 0, 0, 0])],
        document_id="doc-acl-m74",
        allowed_roles=["admin"],
        authorize_as=None,
    )
    response = _ingest(store, INGESTOR, document_id="doc-acl-m74")
    assert response.status_code == 403
    assert _document_rows("doc-acl-m74") == [
        ("internal", "admin-acl.md", "SYNTHETIC ADMIN ACL MARKER")
    ]


def test_mixed_classification_document_is_all_or_nothing(store: Any) -> None:
    """Authorization is document-level: one inaccessible chunk protects every chunk."""
    _insert_raw_chunk("doc-mixed-m74", "mixed.md", 0, "SYNTHETIC INTERNAL PART", "internal")
    _insert_raw_chunk("doc-mixed-m74", "mixed.md", 1, "SYNTHETIC RESTRICTED PART", "restricted")
    original = [
        ("internal", "mixed.md", "SYNTHETIC INTERNAL PART"),
        ("restricted", "mixed.md", "SYNTHETIC RESTRICTED PART"),
    ]

    assert _ingest(store, INGESTOR, document_id="doc-mixed-m74").status_code == 403
    assert _document_rows("doc-mixed-m74") == original

    assert _ingest(store, ADMIN, document_id="doc-mixed-m74").status_code == 200
    replaced = _document_rows("doc-mixed-m74")
    assert replaced
    assert all(row[1] == "employee_security_policy.md" for row in replaced)
    assert not any("SYNTHETIC" in row[2] and "PART" in row[2] for row in replaced)


def test_admin_can_replace_restricted_document(store: Any) -> None:
    _seed_restricted_document(store)
    response = _ingest(
        store, ADMIN, document_id="doc-restricted-m71", classification="restricted"
    )
    assert response.status_code == 200
    rows = _document_rows("doc-restricted-m71")
    assert rows
    assert all(row[:2] == ("restricted", "employee_security_policy.md") for row in rows)
    assert not any("SYNTHETIC RESTRICTED MARKER" in row[2] for row in rows)


def test_ingestor_can_replace_document_it_may_access(store: Any) -> None:
    from app.auth.permissions import Classification

    store.upsert_chunks(
        "tenant-a",
        "internal-guide.md",
        Classification.INTERNAL,
        [(0, "SYNTHETIC OLD INTERNAL CONTENT", [1.0, 0, 0, 0])],
        document_id="doc-internal-m74",
        authorize_as=None,
    )
    response = _ingest(
        store, INGESTOR, document_id="doc-internal-m74", source="cloud_operations_guide.md"
    )
    assert response.status_code == 200
    rows = _document_rows("doc-internal-m74")
    assert rows
    assert all(row[:2] == ("internal", "cloud_operations_guide.md") for row in rows)


def test_new_document_id_ingests_normally(store: Any) -> None:
    response = _ingest(store, INGESTOR, document_id="doc-new-m74")
    assert response.status_code == 200
    assert response.json()["chunks_ingested"] > 0
    rows = _document_rows("doc-new-m74")
    assert rows
    assert all(row[:2] == ("internal", "employee_security_policy.md") for row in rows)


def test_same_document_id_in_another_tenant_is_independent(store: Any) -> None:
    """RLS scopes the existing-document check: tenant B neither sees nor touches A's row."""
    _seed_restricted_document(store)
    response = _ingest(
        store,
        INGESTOR_B_HEADERS,
        document_id="doc-restricted-m71",
    )
    assert response.status_code == 200
    assert _document_rows("doc-restricted-m71") == RESTRICTED_ROWS
    tenant_b_rows = _document_rows("doc-restricted-m71", tenant="tenant-b")
    assert tenant_b_rows
    assert all(row[:2] == ("internal", "employee_security_policy.md") for row in tenant_b_rows)


def test_rls_blocks_cross_tenant_update(store: Any) -> None:
    """Tenant A cannot modify tenant B's rows even with an explicit predicate."""
    with app_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', 'tenant-a', true)")
        cur.execute(
            "UPDATE document_chunks SET content = %s WHERE tenant_id = %s",
            ("tampered", "tenant-b"),
        )
        assert cur.rowcount == 0
    with app_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', 'tenant-b', true)")
        cur.execute("SELECT content FROM document_chunks")
        assert [r[0] for r in cur.fetchall()] == ["tenant B secret"]


# === M8.4: verified JWT identity through real PostgreSQL row-level security ===
#
# Every request below carries a signed synthetic access token from the
# in-process test issuer (app/tests/identity.py) and is verified by the
# production OidcVerifier. The services and VectorStore are real and run as the
# NOSUPERUSER NOBYPASSRLS runtime role; only Bedrock and the embedding client
# are faked. Row visibility and mutations are checked with real SQL.

A_SECRET, B_SECRET = "tenant A secret", "tenant B secret"
CONFIDENTIAL_MARKER = "SYNTHETIC CONFIDENTIAL MARKER"
RESTRICTED_MARKER = "SYNTHETIC RESTRICTED MARKER"
FORGED_IDENTITY = {"X-Tenant-Id": "tenant-b", "X-Tenant-Role": "admin"}
FORGER_KEY = new_key()  # never published in the test JWKS
GENERIC_401 = {"detail": "Not authenticated"}
GENERIC_403 = {"detail": "Forbidden"}


@pytest.fixture()
def bound_tenants(store: Any, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every tenant the store binds into a database session."""
    bound: list[str] = []
    original = store._connect_as

    def spy(tenant_id: str) -> Any:
        bound.append(tenant_id)
        return original(tenant_id)

    monkeypatch.setattr(store, "_connect_as", spy)
    return bound


def _fake_bedrock() -> tuple[Any, Any]:
    from unittest.mock import MagicMock

    from app.clients.bedrock import BedrockService

    model = MagicMock()
    model.converse.return_value = {
        "output": {"message": {"content": [{"text": "SYNTHETIC answer [1]"}]}},
        "usage": {"inputTokens": 1, "outputTokens": 1},
    }
    return BedrockService(client=model), model


def _query_as(store: Any, headers: dict[str, str]) -> tuple[Any, str | None]:
    """POST /v1/query through the real RagService and store; return the model prompt."""
    from fastapi.testclient import TestClient

    from app.api.dependencies import get_rag_service
    from app.main import app

    service, fake = _api_rag_service(store)
    app.dependency_overrides[get_rag_service] = lambda: service
    try:
        response = TestClient(app).post(
            "/v1/query", json={"question": "Show me every secret."}, headers=headers
        )
    finally:
        app.dependency_overrides.pop(get_rag_service)
    prompt = (
        fake.converse.call_args.kwargs["messages"][0]["content"][0]["text"]
        if fake.converse.called
        else None
    )
    return response, prompt


def _generate_as(headers: dict[str, str]) -> tuple[Any, Any]:
    from fastapi.testclient import TestClient

    from app.api.dependencies import get_bedrock_service
    from app.main import app

    bedrock, model = _fake_bedrock()
    app.dependency_overrides[get_bedrock_service] = lambda: bedrock
    try:
        response = TestClient(app).post("/v1/generate", json={"prompt": "p"}, headers=headers)
    finally:
        app.dependency_overrides.pop(get_bedrock_service)
    return response, model


def _snapshots() -> dict[str, list[tuple[Any, ...]]]:
    return {tenant: _tenant_snapshot(tenant) for tenant in ("tenant-a", "tenant-b")}


def _token_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed_confidential_document(store: Any) -> None:
    from app.auth.permissions import Classification

    store.upsert_chunks(
        "tenant-a",
        "confidential-plan.md",
        Classification.CONFIDENTIAL,
        [(0, CONFIDENTIAL_MARKER, [1.0, 0, 0, 0])],
        document_id="doc-confidential-m84",
        authorize_as=None,
    )


# --- precondition: row security is live for the runtime role ------------------


def test_rls_id_00_policy_is_active_and_missing_context_exposes_nothing(store: Any) -> None:
    """The isolation below is enforced by PostgreSQL, not inferred from app code."""
    with psycopg.connect(ADMIN_URL or "") as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = %s",
            ("document_chunks",),
        )
        assert cur.fetchone() == (True, True)
        cur.execute(
            "SELECT policyname, cmd, permissive, qual, with_check FROM pg_policies "
            "WHERE tablename = %s",
            ("document_chunks",),
        )
        policies = cur.fetchall()
        # The superuser bypasses RLS, so this proves rows exist for both tenants.
        cur.execute("SELECT tenant_id, count(*) FROM document_chunks GROUP BY 1 ORDER BY 1")
        assert cur.fetchall() == [("tenant-a", 1), ("tenant-b", 1)]
    assert len(policies) == 1
    name, cmd, permissive, qual, with_check = policies[0]
    assert (name, cmd, permissive) == ("tenant_isolation", "ALL", "PERMISSIVE")
    for expression in (qual, with_check):
        assert "current_setting('app.tenant_id'" in expression

    with app_connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT rolsuper, rolbypassrls, current_setting('row_security') "
            "FROM pg_roles WHERE rolname = current_user"
        )
        assert cur.fetchone() == (False, False, "on")
        # No tenant context, an empty one and an unknown one all match nothing.
        cur.execute("SELECT count(*) FROM document_chunks")
        assert cur.fetchone() == (0,)
        for unbound in ("", "tenant-z"):
            cur.execute("SELECT set_config('app.tenant_id', %s, true)", (unbound,))
            cur.execute("SELECT count(*) FROM document_chunks")
            assert cur.fetchone() == (0,), unbound
        conn.rollback()
        # Without a tenant context nothing can be written for any tenant either.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute(
                "INSERT INTO document_chunks (tenant_id, document_id, source, chunk_index, "
                "content, classification, allowed_roles, embedding) "
                "VALUES ('tenant-a', 'doc-unbound', 'u.md', 0, 'x', 'internal', '{}', "
                "%s::vector)",
                (vec([1.0, 0, 0, 0]),),
            )
        conn.rollback()


# --- RLS-ID-01: a verified tenant-A token reads only tenant-A rows ------------


def test_rls_id_01_verified_tokens_read_only_their_own_tenant(
    store: Any, bound_tenants: list[str]
) -> None:
    response, prompt = _query_as(store, TENANT_A_HEADERS)
    assert response.status_code == 200
    assert prompt is not None and A_SECRET in prompt and B_SECRET not in prompt
    assert B_SECRET not in response.text
    assert [c["source"] for c in response.json()["citations"]] == ["a.md"]

    response, prompt = _query_as(store, TENANT_B_HEADERS)
    assert response.status_code == 200
    assert prompt is not None and B_SECRET in prompt and A_SECRET not in prompt
    assert [c["source"] for c in response.json()["citations"]] == ["b.md"]
    # The only tenants ever bound into a database session are the verified ones.
    assert bound_tenants == ["tenant-a", "tenant-b"]


# --- RLS-ID-02: forged identity headers change nothing ------------------------


def test_rls_id_02a_forged_headers_cannot_redirect_a_verified_query(
    store: Any, bound_tenants: list[str]
) -> None:
    response, prompt = _query_as(store, {**TENANT_A_HEADERS, **FORGED_IDENTITY})
    assert response.status_code == 200
    assert prompt is not None and A_SECRET in prompt and B_SECRET not in prompt
    assert [c["source"] for c in response.json()["citations"]] == ["a.md"]
    assert bound_tenants == ["tenant-a"]


def test_rls_id_02b_forged_headers_cannot_redirect_a_verified_write(
    store: Any, bound_tenants: list[str]
) -> None:
    before_b = _tenant_snapshot("tenant-b")
    response = _ingest(store, {**INGESTOR_A_HEADERS, **FORGED_IDENTITY}, document_id="doc-m84")
    assert response.status_code == 200
    rows = _document_rows("doc-m84", tenant="tenant-a")
    assert rows and all(row[:2] == ("internal", "employee_security_policy.md") for row in rows)
    assert _document_rows("doc-m84", tenant="tenant-b") == []
    assert _tenant_snapshot("tenant-b") == before_b
    assert bound_tenants == ["tenant-a"]


def test_rls_id_02c_tenant_a_cannot_replace_tenant_b_document_by_id(
    store: Any, bound_tenants: list[str]
) -> None:
    """Targeting tenant B's document_id writes a separate tenant-A document only."""
    before_b = _tenant_snapshot("tenant-b")
    for headers in (
        {**INGESTOR_A_HEADERS, **FORGED_IDENTITY},
        {**ADMIN_A_HEADERS, **FORGED_IDENTITY},
    ):
        response = _ingest(store, headers, document_id="doc-b")
        assert response.status_code == 200
    assert _tenant_snapshot("tenant-b") == before_b
    assert _document_rows("doc-b", tenant="tenant-b") == [("internal", "b.md", B_SECRET)]
    rows_a = _document_rows("doc-b", tenant="tenant-a")
    assert rows_a and all(row[1] == "employee_security_policy.md" for row in rows_a)
    assert bound_tenants == ["tenant-a", "tenant-a"]


# --- RLS-ID-03: forged headers without a token authenticate nothing -----------


def test_rls_id_03_forged_headers_without_token_are_rejected_before_the_database(
    store: Any, bound_tenants: list[str]
) -> None:
    before = _snapshots()
    for headers in (FORGED_IDENTITY, {"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "admin"}):
        response, prompt = _query_as(store, headers)
        assert (response.status_code, response.json(), prompt) == (401, GENERIC_401, None)
        assert response.headers["WWW-Authenticate"] == "Bearer"
        response = _ingest(store, headers, document_id="doc-b")
        assert (response.status_code, response.json()) == (401, GENERIC_401)
        response, model = _generate_as(headers)
        assert (response.status_code, response.json()) == (401, GENERIC_401)
        model.converse.assert_not_called()
    assert _snapshots() == before
    assert bound_tenants == []


# --- RLS-ID-04: reader, ingestor and admin over real rows ---------------------


@pytest.mark.parametrize(
    ("headers", "visible", "hidden"),
    [
        (TENANT_A_HEADERS, {A_SECRET}, {CONFIDENTIAL_MARKER, RESTRICTED_MARKER}),
        (INGESTOR_A_HEADERS, {A_SECRET, CONFIDENTIAL_MARKER}, {RESTRICTED_MARKER}),
        (ADMIN_A_HEADERS, {A_SECRET, CONFIDENTIAL_MARKER, RESTRICTED_MARKER}, set()),
    ],
    ids=["reader", "ingestor", "admin"],
)
def test_rls_id_04a_verified_role_bounds_row_visibility(
    store: Any, headers: dict[str, str], visible: set[str], hidden: set[str]
) -> None:
    _seed_confidential_document(store)
    _seed_restricted_document(store)
    response, prompt = _query_as(store, headers)
    assert response.status_code == 200
    assert prompt is not None
    for marker in visible:
        assert marker in prompt, marker
    for marker in hidden | {B_SECRET}:
        assert marker not in prompt, marker
        assert marker not in response.text, marker


def test_rls_id_04b_reader_cannot_generate_or_write(
    store: Any, bound_tenants: list[str]
) -> None:
    before = _snapshots()
    response, model = _generate_as(TENANT_A_HEADERS)
    assert response.status_code == 403
    model.converse.assert_not_called()
    response = _ingest(store, TENANT_A_HEADERS, document_id="doc-a")
    assert response.status_code == 403
    assert _snapshots() == before
    assert bound_tenants == []


def test_rls_id_04c_ingestor_and_admin_write_authority_over_real_rows(
    store: Any, bound_tenants: list[str]
) -> None:
    _seed_restricted_document(store)
    bound_tenants.clear()  # the operator seed above is not a request
    before = _snapshots()
    # Ingestor: may not create restricted content (route) ...
    response = _ingest(
        store, INGESTOR_A_HEADERS, document_id="doc-new-m84", classification="restricted"
    )
    assert response.status_code == 403
    assert bound_tenants == []
    # ... nor replace an existing restricted document (in the store transaction).
    response = _ingest(store, INGESTOR_A_HEADERS, document_id="doc-restricted-m71")
    assert response.status_code == 403
    assert bound_tenants == ["tenant-a"]
    assert _snapshots() == before
    response, model = _generate_as(INGESTOR_A_HEADERS)
    assert response.status_code == 403
    model.converse.assert_not_called()

    # Admin of the same tenant may do both.
    response = _ingest(
        store, ADMIN_A_HEADERS, document_id="doc-restricted-m71", classification="restricted"
    )
    assert response.status_code == 200
    rows = _document_rows("doc-restricted-m71")
    assert rows and all(row[:2] == ("restricted", "employee_security_policy.md") for row in rows)
    assert not any(RESTRICTED_MARKER in row[2] for row in rows)
    response, model = _generate_as(ADMIN_A_HEADERS)
    assert response.status_code == 200
    model.converse.assert_called_once()
    assert _tenant_snapshot("tenant-b") == before["tenant-b"]


# --- RLS-ID-05: missing, invalid and unmappable tokens never reach the database --


def _b64url_json(value: dict[str, Any]) -> str:
    import base64
    import json

    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def _tamper_payload(token: str) -> str:
    """Splice a tenant-B admin payload under a valid tenant-A reader signature."""
    header, _, signature = token.split(".")
    payload = _b64url_json(claims(["tenant:tenant-b", "role:admin"]))
    return f"{header}.{payload}.{signature}"


def _unsigned(body: dict[str, Any]) -> str:
    """An alg=none token with an empty signature segment."""
    header = _b64url_json({"alg": "none", "typ": "JWT", "kid": TEST_KID})
    return f"{header}.{_b64url_json(body)}."


def _invalid_token(kind: str) -> str:
    from collections.abc import Callable

    body = claims(["tenant:tenant-a", "role:admin"])
    tokens: dict[str, Callable[[], str]] = {
        "expired": lambda: sign({**body, "iat": body["iat"] - 7200, "exp": body["iat"] - 3600}),
        "forged_signature": lambda: sign(body, key=FORGER_KEY),
        "unknown_kid": lambda: sign(body, key=FORGER_KEY, kid="never-published-m84"),
        "wrong_issuer": lambda: sign({**body, "iss": "https://issuer.invalid"}),
        "wrong_client": lambda: sign({**body, "client_id": "other-client"}),
        "id_token": lambda: sign({**body, "token_use": "id"}),
        "alg_none": lambda: _unsigned(body),
        "tampered_payload": lambda: _tamper_payload(
            TENANT_A_HEADERS["Authorization"].removeprefix("Bearer ")
        ),
        "malformed": lambda: "not.a.jwt",
    }
    return tokens[kind]()


@pytest.mark.parametrize(
    "kind",
    [
        "expired",
        "forged_signature",
        "unknown_kid",
        "wrong_issuer",
        "wrong_client",
        "id_token",
        "alg_none",
        "tampered_payload",
        "malformed",
    ],
)
def test_rls_id_05a_invalid_tokens_are_401_with_no_database_access(
    store: Any, bound_tenants: list[str], kind: str
) -> None:
    before = _snapshots()
    headers = _token_headers(_invalid_token(kind))
    response, prompt = _query_as(store, headers)
    assert (response.status_code, response.json(), prompt) == (401, GENERIC_401, None)
    response = _ingest(store, headers, document_id="doc-b")
    assert (response.status_code, response.json()) == (401, GENERIC_401)
    assert _snapshots() == before
    assert bound_tenants == []


@pytest.mark.parametrize(
    "groups",
    [
        ["tenant:tenant-z", "role:admin"],
        ["tenant:tenant-a", "tenant:tenant-b", "role:admin"],
        ["tenant:tenant-a", "role:reader", "role:admin"],
        ["tenant:tenant-a"],
        ["role:admin"],
        ["tenant:tenant-b", "role:superuser"],
        ["Tenant:tenant-b", "role:admin"],
        None,
    ],
)
def test_rls_id_05b_unmappable_identities_are_403_with_no_database_access(
    store: Any, bound_tenants: list[str], groups: list[str] | None
) -> None:
    before = _snapshots()
    headers = _token_headers(sign(claims(groups)))
    response, prompt = _query_as(store, headers)
    assert (response.status_code, response.json(), prompt) == (403, GENERIC_403, None)
    response = _ingest(store, headers, document_id="doc-b")
    assert (response.status_code, response.json()) == (403, GENERIC_403)
    assert _snapshots() == before
    assert bound_tenants == []


def test_rls_id_05c_missing_token_is_401_with_no_database_access(
    store: Any, bound_tenants: list[str]
) -> None:
    before = _snapshots()
    for headers in ({}, {"Authorization": "Bearer "}, {"Authorization": "Basic dXNlcjpwYXNz"}):
        response, prompt = _query_as(store, headers)
        assert (response.status_code, response.json(), prompt) == (401, GENERIC_401, None)
        response = _ingest(store, headers, document_id="doc-b")
        assert (response.status_code, response.json()) == (401, GENERIC_401)
    assert _snapshots() == before
    assert bound_tenants == []


# --- RLS-ID-06: session context across consecutive and concurrent requests ----


def test_rls_id_06a_interleaved_requests_never_carry_tenant_context_over(
    store: Any, bound_tenants: list[str]
) -> None:
    sequence = ["tenant-a", "tenant-b", "tenant-b", "tenant-a", "tenant-b", "tenant-a"] * 2
    headers = {"tenant-a": TENANT_A_HEADERS, "tenant-b": TENANT_B_HEADERS}
    own = {"tenant-a": (A_SECRET, B_SECRET), "tenant-b": (B_SECRET, A_SECRET)}
    for tenant in sequence:
        response, prompt = _query_as(store, headers[tenant])
        assert response.status_code == 200
        mine, theirs = own[tenant]
        assert prompt is not None and mine in prompt and theirs not in prompt, tenant
    assert bound_tenants == sequence

    # Interleaved writes to the SAME document_id stay in their own tenants.
    writes = [
        (INGESTOR_A_HEADERS, "employee_security_policy.md"),
        (INGESTOR_B_HEADERS, "employee_security_policy.md"),
        (INGESTOR_A_HEADERS, "cloud_operations_guide.md"),
    ]
    for write_headers, source in writes:
        response = _ingest(store, write_headers, document_id="doc-shared-m84", source=source)
        assert response.status_code == 200
    rows_a = _document_rows("doc-shared-m84", tenant="tenant-a")
    rows_b = _document_rows("doc-shared-m84", tenant="tenant-b")
    assert rows_a and all(row[1] == "cloud_operations_guide.md" for row in rows_a)
    assert rows_b and all(row[1] == "employee_security_policy.md" for row in rows_b)
    assert bound_tenants[len(sequence):] == ["tenant-a", "tenant-b", "tenant-a"]


def test_rls_id_06b_concurrent_tenant_requests_stay_isolated(store: Any) -> None:
    """Requests from both tenants are held in flight together, then retrieve."""
    import re
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from unittest.mock import MagicMock

    from fastapi.testclient import TestClient

    from app.api.dependencies import get_rag_service
    from app.main import app
    from app.rag.service import RagService

    workers, total = 8, 24
    barrier = threading.Barrier(workers, timeout=20)
    prompts: dict[int, str] = {}

    def embed(question: str) -> list[float]:
        barrier.wait()  # every worker's request is in flight before any retrieves
        return [1.0, 0, 0, 0]

    def converse(**kwargs: Any) -> dict[str, Any]:
        text = kwargs["messages"][0]["content"][0]["text"]
        match = re.search(r"probe (\d+) end", text)
        assert match is not None
        prompts[int(match.group(1))] = text
        return {
            "output": {"message": {"content": [{"text": "SYNTHETIC answer [1]"}]}},
            "usage": {"inputTokens": 1, "outputTokens": 1},
        }

    from app.clients.bedrock import BedrockService

    embeddings = MagicMock()
    embeddings.embed.side_effect = embed
    model = MagicMock()
    model.converse.side_effect = converse
    service = RagService(bedrock=BedrockService(client=model), embeddings=embeddings, store=store)
    tenants = ["tenant-a" if i % 2 == 0 else "tenant-b" for i in range(total)]
    headers = {"tenant-a": TENANT_A_HEADERS, "tenant-b": TENANT_B_HEADERS}

    def call(i: int) -> tuple[int, Any]:
        response = TestClient(app).post(
            "/v1/query", json={"question": f"probe {i} end"}, headers=headers[tenants[i]]
        )
        return i, response

    app.dependency_overrides[get_rag_service] = lambda: service
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(call, range(total)))
    finally:
        app.dependency_overrides.pop(get_rag_service)

    assert len(prompts) == total
    for i, response in results:
        assert response.status_code == 200, i
        mine, theirs = (A_SECRET, B_SECRET) if tenants[i] == "tenant-a" else (B_SECRET, A_SECRET)
        assert mine in prompts[i] and theirs not in prompts[i], i
        expected = "a.md" if tenants[i] == "tenant-a" else "b.md"
        assert [c["source"] for c in response.json()["citations"]] == [expected], i


def test_rls_id_06c_tenant_binding_is_transaction_scoped_on_a_reused_connection(
    store: Any,
) -> None:
    """A committed or rolled-back transaction leaves the session with no tenant.

    VectorStore opens a fresh connection per operation today. This proves that
    even a reused (pooled) connection would fail closed between requests.
    """
    conn = store._connect_as("tenant-a")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT content FROM document_chunks")
            assert [r[0] for r in cur.fetchall()] == [A_SECRET]
        conn.commit()
        with conn.cursor() as cur:
            cur.execute("SELECT coalesce(current_setting('app.tenant_id', true), '')")
            assert cur.fetchone() == ("",)
            cur.execute("SELECT content FROM document_chunks WHERE tenant_id = 'tenant-a'")
            assert cur.fetchall() == []
        conn.rollback()

        # Rebinding the same connection to tenant B exposes only tenant B.
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.tenant_id', 'tenant-b', true)")
            cur.execute("SELECT content FROM document_chunks")
            assert [r[0] for r in cur.fetchall()] == [B_SECRET]
        conn.rollback()  # an aborted request must not leak its binding either
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM document_chunks")
            assert cur.fetchone() == (0,)
        conn.rollback()
    finally:
        conn.close()


def test_rls_id_06d_each_store_operation_uses_its_own_closed_connection(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No connection, and therefore no session state, outlives a request."""
    connections: list[Any] = []
    original = store._connect

    def recording_connect() -> Any:
        conn = original()
        connections.append(conn)
        return conn

    monkeypatch.setattr(store, "_connect", recording_connect)
    for headers in (TENANT_A_HEADERS, TENANT_B_HEADERS, TENANT_A_HEADERS):
        response, _ = _query_as(store, headers)
        assert response.status_code == 200
    assert _ingest(store, INGESTOR_B_HEADERS, document_id="doc-conn-m84").status_code == 200
    assert len(connections) == 4
    assert len({id(c) for c in connections}) == 4
    assert all(c.closed for c in connections)
