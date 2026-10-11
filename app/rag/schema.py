"""Schema and privilege initialization - runs as an administrative role.

Privilege separation is a security control, not a convenience:

* **Admin connection** creates the pgvector extension, owns
  `document_chunks`, declares the row-security policy, and provisions the
  runtime role. Only DDL runs here. Locally this is a superuser; on Amazon
  RDS it is the master user, which is *not* a PostgreSQL superuser, so
  nothing here may depend on superuser-only statements.
* **Runtime connection** uses a dedicated login role created `NOSUPERUSER
  NOBYPASSRLS`. This is mandatory, not cosmetic: PostgreSQL exempts
  superusers and roles holding BYPASSRLS from row-level security
  *unconditionally*. `FORCE ROW LEVEL SECURITY` removes only the
  table-owner exemption, so a service connecting as a superuser silently
  gets no row-security enforcement at all (see docs/security/FINDINGS.md,
  F-001).

Identifiers and passwords are composed with psycopg.sql, never string
interpolation.
"""
from typing import Any

import psycopg
from psycopg import sql

SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS document_chunks (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL,
    chunk_index INT NOT NULL,
    content TEXT NOT NULL,
    embedding vector(%(dims)s) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, chunk_index)
);
ALTER TABLE document_chunks ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE document_chunks ADD COLUMN IF NOT EXISTS document_id TEXT;
ALTER TABLE document_chunks ADD COLUMN IF NOT EXISTS classification TEXT;
ALTER TABLE document_chunks ADD COLUMN IF NOT EXISTS allowed_roles TEXT[] DEFAULT '{}';
UPDATE document_chunks SET tenant_id = 'unassigned' WHERE tenant_id IS NULL;
UPDATE document_chunks SET classification = 'restricted' WHERE classification IS NULL;
UPDATE document_chunks SET document_id = source WHERE document_id IS NULL;
UPDATE document_chunks SET allowed_roles = '{}' WHERE allowed_roles IS NULL;
ALTER TABLE document_chunks ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE document_chunks ALTER COLUMN classification SET NOT NULL;
ALTER TABLE document_chunks ALTER COLUMN document_id SET NOT NULL;
ALTER TABLE document_chunks ALTER COLUMN allowed_roles SET NOT NULL;

ALTER TABLE document_chunks DROP CONSTRAINT IF EXISTS document_chunks_source_chunk_index_key;
CREATE UNIQUE INDEX IF NOT EXISTS document_chunks_tenant_source_idx
    ON document_chunks (tenant_id, source, chunk_index);
CREATE INDEX IF NOT EXISTS document_chunks_tenant_class_idx
    ON document_chunks (tenant_id, classification);
CREATE INDEX IF NOT EXISTS document_chunks_tenant_document_idx
    ON document_chunks (tenant_id, document_id);
CREATE INDEX IF NOT EXISTS document_chunks_embedding_idx
    ON document_chunks USING hnsw (embedding vector_cosine_ops);

-- Row-level security: the database enforces isolation independently of the
-- application. FORCE removes the table-owner exemption; the runtime role is
-- provisioned NOBYPASSRLS so it cannot be exempt either.
ALTER TABLE document_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_chunks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON document_chunks;
CREATE POLICY tenant_isolation ON document_chunks
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
"""


class RuntimeRoleOverprivilegedError(RuntimeError):
    """The runtime role holds an attribute it must never have."""


# Attributes that would let the runtime role escape row-level security or
# create its way around it. Order matches the SELECT in _ensure_app_role.
_FORBIDDEN_ROLE_ATTRIBUTES = ("rolsuper", "rolbypassrls", "rolcreatedb", "rolcreaterole")


def _ensure_app_role(conn: psycopg.Connection[Any], role: str, password: str) -> None:
    """Create the runtime login role, or validate an existing one, then grant access.

    An existing role is validated, never altered. Changing SUPERUSER or
    BYPASSRLS needs a PostgreSQL superuser even to switch them off, which the
    RDS master user is not, and silently repairing an overprivileged role
    would hide how it got that way. Any forbidden attribute fails closed: no
    grant is issued and the caller's transaction is rolled back.
    """
    role_ident = sql.Identifier(role)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole "
            "FROM pg_roles WHERE rolname = %s",
            (role,),
        )
        row = cur.fetchone()
        if row is None:
            cur.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} "
                    "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT"
                ).format(role_ident, sql.Literal(password))
            )
        else:
            held = [
                name
                for name, value in zip(_FORBIDDEN_ROLE_ATTRIBUTES, row, strict=True)
                if value
            ]
            if held:
                raise RuntimeRoleOverprivilegedError(
                    f"runtime role '{role}' already exists with forbidden attributes "
                    f"({', '.join(held)}); refusing to grant it access"
                )
        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(role_ident))
        cur.execute(
            sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON document_chunks TO {}"
            ).format(role_ident)
        )
        cur.execute(
            sql.SQL("GRANT USAGE, SELECT ON SEQUENCE document_chunks_id_seq TO {}").format(
                role_ident
            )
        )


def initialize_schema(
    admin_conninfo: str,
    *,
    dimensions: int,
    app_role: str,
    app_password: str,
) -> None:
    """Create the schema, policy and runtime role using an administrative connection."""
    with psycopg.connect(admin_conninfo) as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL.replace("%(dims)s", str(int(dimensions))))
        _ensure_app_role(conn, app_role, app_password)


def assert_no_rls_bypass(conninfo: str) -> tuple[bool, bool]:
    """Return (rolsuper, rolbypassrls) for the connecting role.

    Both must be False for row-level security to apply. Exposed as a helper so
    the same check can run in tests and as a deployment preflight.
    """
    with psycopg.connect(conninfo) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        )
        row = cur.fetchone()
    if row is None:  # pragma: no cover - current_user always exists in pg_roles
        raise RuntimeError("could not resolve current_user in pg_roles")
    return bool(row[0]), bool(row[1])
