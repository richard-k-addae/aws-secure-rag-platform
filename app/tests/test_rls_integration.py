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
    )
    st.upsert_chunks(
        "tenant-b",
        "b.md",
        Classification.INTERNAL,
        [(0, "tenant B secret", [1.0, 0, 0, 0])],
        document_id="doc-b",
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
            headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "reader"},
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
    )


def _ingest_as_ingestor_reusing_document_id(store: Any) -> int:
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
        response = TestClient(app).post(
            "/v1/documents/ingest",
            json={
                "source": "employee_security_policy.md",
                "classification": "internal",
                "document_id": "doc-restricted-m71",
            },
            headers={"X-Tenant-Id": "tenant-a", "X-Tenant-Role": "ingestor"},
        )
    finally:
        app.dependency_overrides.pop(get_ingestion_service)
    return int(response.status_code)


def _restricted_document_rows() -> list[tuple[str, str, str]]:
    with app_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', 'tenant-a', true)")
        cur.execute(
            "SELECT classification, source, content FROM document_chunks "
            "WHERE document_id = %s ORDER BY chunk_index",
            ("doc-restricted-m71",),
        )
        return [(r[0], r[1], r[2]) for r in cur.fetchall()]


def test_characterize_ingestor_document_id_reuse_destroys_restricted_document(
    store: Any,
) -> None:
    """M7 AUTHZ-01 evidence: CURRENT behavior, asserted as-is.

    An ingestor cannot read RESTRICTED content, yet reusing a restricted
    document's document_id at a classification it may submit deletes the
    restricted chunks and replaces them with its own. RLS does not stop this
    because the write is inside the caller's own tenant. This test fails once
    the ingest path is fixed (M7.4); replace it then, do not weaken it.
    """
    _seed_restricted_document(store)
    assert _restricted_document_rows() == [
        ("restricted", "restricted-incident.md", "SYNTHETIC RESTRICTED MARKER")
    ]

    assert _ingest_as_ingestor_reusing_document_id(store) == 200

    rows = _restricted_document_rows()
    assert rows, "document_id now has no chunks at all"
    assert all(classification == "internal" for classification, _, _ in rows)
    assert all(source == "employee_security_policy.md" for _, source, _ in rows)
    assert not any("SYNTHETIC RESTRICTED MARKER" in content for _, _, content in rows)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="M7 AUTHZ-01: ingest does not check the existing document's clearance",
)
def test_ingestor_cannot_overwrite_restricted_document_by_id(store: Any) -> None:
    """Secure invariant: the restricted document survives unmodified.

    Holds whether the fix rejects the request or makes it a no-op.
    """
    _seed_restricted_document(store)
    _ingest_as_ingestor_reusing_document_id(store)
    assert _restricted_document_rows() == [
        ("restricted", "restricted-incident.md", "SYNTHETIC RESTRICTED MARKER")
    ]


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
