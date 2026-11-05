"""One-shot database bootstrap, run as the command of a dedicated Fargate task.

Reads the RDS master secret and the rag_app runtime secret with the task
role, applies the schema with the hardened code already in the image
(app.rag.schema), then verifies the result and proves row-level security
with a synthetic row that is rolled back.

Nothing secret is ever printed: only fixed markers, object names and
versions. Every failure exits nonzero with a scrubbed, one-line reason.
"""
import json
import os
import sys
import uuid
from urllib.parse import quote

REDACT: list[str] = []


def scrub(text: str) -> str:
    for secret in REDACT:
        if secret:
            text = text.replace(secret, "***")
    return " ".join(text.split())[:400]


class BootstrapError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BootstrapError(message)


def main() -> None:
    import boto3
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    from app.rag.schema import initialize_schema

    region = os.environ["AWS_REGION"]
    db_host = os.environ["DB_HOST"]
    db_port = int(os.environ["DB_PORT"])
    db_name = os.environ["DB_NAME"]
    ca_file = os.environ["DB_SSLROOTCERT"]
    app_role = os.environ["APP_DB_ROLE"]
    dims = int(os.environ["EMBEDDING_DIMENSIONS"])

    require(os.path.isfile(ca_file), "RDS CA bundle is missing from the image")

    # --- secrets: fetched with the task role, held in memory only -----------
    secrets = boto3.client("secretsmanager", region_name=region)
    master = json.loads(
        secrets.get_secret_value(SecretId=os.environ["DB_MASTER_SECRET_ARN"])["SecretString"]
    )
    runtime = json.loads(
        secrets.get_secret_value(SecretId=os.environ["DB_RUNTIME_SECRET_ARN"])["SecretString"]
    )
    admin_user, admin_password = str(master["username"]), str(master["password"])
    runtime_url = str(runtime["DATABASE_URL"])
    REDACT.extend([admin_password, runtime_url, quote(admin_password, safe="")])

    # RDS-managed secrets carry only username and password; host and port come
    # from the task definition unless AWS includes them.
    admin_host = str(master.get("host") or db_host)
    admin_port = int(master.get("port") or db_port)
    admin_url = (
        f"postgresql://{quote(admin_user, safe='')}:{quote(admin_password, safe='')}"
        f"@{admin_host}:{admin_port}/{quote(db_name, safe='')}"
        f"?sslmode=verify-full&sslrootcert={quote(ca_file, safe='/')}"
    )
    REDACT.append(admin_url)

    runtime_params = conninfo_to_dict(runtime_url)
    app_password = str(runtime_params.get("password") or "")
    REDACT.append(app_password)
    require(bool(app_password), "runtime DATABASE_URL has no password")
    require(runtime_params.get("user") == app_role, "runtime DATABASE_URL user is not the app role")
    require(runtime_params.get("host") == db_host, "runtime DATABASE_URL host is not this database")
    require(runtime_params.get("dbname") == db_name, "runtime DATABASE_URL database is unexpected")
    require(
        runtime_params.get("sslmode") == "verify-full",
        "runtime DATABASE_URL does not use sslmode=verify-full",
    )
    require(
        runtime_params.get("sslrootcert") == ca_file,
        "runtime DATABASE_URL does not use the shipped RDS CA bundle",
    )
    require(admin_user != app_role, "master user and app role must differ")

    # --- admin: verified TLS, then the hardened bootstrap -------------------
    with psycopg.connect(admin_url) as conn, conn.cursor() as cur:
        require(conn.info.pgconn.ssl_in_use, "admin connection is not using TLS")
        cur.execute("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
        row = cur.fetchone()
        require(row is not None and row[0] is True, "server reports admin connection without SSL")
    print("TLS_VERIFY_OK role=admin", flush=True)

    initialize_schema(admin_url, dimensions=dims, app_role=app_role, app_password=app_password)

    with psycopg.connect(admin_url) as conn, conn.cursor() as cur:
        cur.execute("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
        row = cur.fetchone()
        require(row is not None, "pgvector extension is not installed")
        assert row is not None
        print(f"PGVECTOR_OK version={row[0]}", flush=True)

        cur.execute("SELECT to_regclass('public.document_chunks') IS NOT NULL")
        row = cur.fetchone()
        require(row is not None and row[0] is True, "document_chunks table is missing")
        cur.execute(
            "SELECT format_type(atttypid, atttypmod) FROM pg_attribute "
            "WHERE attrelid = 'public.document_chunks'::regclass AND attname = 'embedding'"
        )
        row = cur.fetchone()
        require(
            row is not None and row[0] == f"vector({dims})",
            f"embedding column is not vector({dims})",
        )
        cur.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid = 'public.document_chunks'::regclass"
        )
        row = cur.fetchone()
        require(row is not None and row[0] is True, "row-level security is not enabled")
        assert row is not None
        require(row[1] is True, "row-level security is not forced")
        cur.execute(
            "SELECT count(*) FROM pg_policies WHERE schemaname = 'public' "
            "AND tablename = 'document_chunks' AND policyname = 'tenant_isolation'"
        )
        row = cur.fetchone()
        require(row is not None and row[0] == 1, "tenant_isolation policy is missing")
        print(f"SCHEMA_OK table=document_chunks embedding=vector({dims}) rls=forced", flush=True)

        cur.execute(
            "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole "
            "FROM pg_roles WHERE rolname = %s",
            (app_role,),
        )
        row = cur.fetchone()
        require(row is not None, "runtime role does not exist")
        assert row is not None
        require(
            tuple(row) == (True, False, False, False, False),
            "runtime role attributes are not LOGIN-only least privilege",
        )
        cur.execute(
            "SELECT tableowner FROM pg_tables WHERE schemaname = 'public' "
            "AND tablename = 'document_chunks'"
        )
        row = cur.fetchone()
        require(row is not None and row[0] != app_role, "runtime role owns the table")
        print(f"ROLE_OK role={app_role} login=true least_privilege=true", flush=True)

    # --- runtime: verified TLS as the app role, then a reversible RLS test --
    suffix = uuid.uuid4().hex[:12]
    tenant_a, tenant_b = f"bootstrap-smoke-a-{suffix}", f"bootstrap-smoke-b-{suffix}"
    document = f"bootstrap-smoke-doc-{suffix}"
    vector = "[" + ",".join(["0"] * (dims - 1) + ["1"]) + "]"

    with psycopg.connect(runtime_url) as conn:
        with conn.cursor() as cur:
            require(conn.info.pgconn.ssl_in_use, "runtime connection is not using TLS")
            cur.execute("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            row = cur.fetchone()
            require(
                row is not None and row[0] is True, "server reports runtime connection without SSL"
            )
            cur.execute(
                "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname = current_user"
            )
            row = cur.fetchone()
            require(
                row is not None and row[0] == app_role, "runtime connection is not the app role"
            )
            assert row is not None
            require(row[1] is False and row[2] is False, "runtime role can bypass row security")
            print("TLS_VERIFY_OK role=runtime", flush=True)

            def visible_rows() -> int:
                # No tenant predicate on purpose: only the policy can filter.
                cur.execute(
                    "SELECT count(*) FROM document_chunks WHERE document_id = %s", (document,)
                )
                found = cur.fetchone()
                return int(found[0]) if found else -1

            def use_tenant(tenant: str) -> None:
                cur.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))

            use_tenant(tenant_a)
            cur.execute(
                "INSERT INTO document_chunks (tenant_id, document_id, source, chunk_index, "
                "content, classification, allowed_roles, embedding) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s::vector)",
                (
                    tenant_a,
                    document,
                    "bootstrap-smoke.md",
                    0,
                    "synthetic bootstrap smoke row",
                    "internal",
                    [],
                    vector,
                ),
            )
            require(visible_rows() == 1, "tenant A cannot see its own row")
            use_tenant(tenant_b)
            require(visible_rows() == 0, "tenant B can see tenant A's row")
            use_tenant("")
            require(visible_rows() == 0, "row visible with no tenant context")
        # The synthetic row is never committed, pass or fail.
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_a,))
            cur.execute("SELECT count(*) FROM document_chunks WHERE document_id = %s", (document,))
            row = cur.fetchone()
            require(row is not None and row[0] == 0, "synthetic row was not rolled back")
        conn.rollback()
    print("RLS_OK tenant_isolation=enforced synthetic_row=rolled_back", flush=True)
    print("DB_BOOTSTRAP_PASS", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - one scrubbed line, never a traceback
        code = ""
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            code = str(response.get("Error", {}).get("Code", ""))
        code = code or str(getattr(exc, "sqlstate", "") or "")
        print(
            f"DB_BOOTSTRAP_FAIL {type(exc).__name__} code={code or '-'} message={scrub(str(exc))}",
            flush=True,
        )
        sys.exit(1)
