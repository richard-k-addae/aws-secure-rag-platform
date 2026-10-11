"""Runtime-role provisioning: create once, validate on re-run, fail closed.

These run without a database. They pin the statements `_ensure_app_role`
issues, because the bootstrap must work under an administrative role that is
not a PostgreSQL superuser (the Amazon RDS master user). The same behaviour is
exercised against a real PostgreSQL in test_rls_integration.py.
"""
from typing import Any

import pytest

psycopg = pytest.importorskip("psycopg")

from app.rag.schema import RuntimeRoleOverprivilegedError, _ensure_app_role  # noqa: E402

# (rolsuper, rolbypassrls, rolcreatedb, rolcreaterole)
LEAST_PRIVILEGE = (False, False, False, False)


class FakeCursor:
    def __init__(self, role_row: tuple[bool, ...] | None, statements: list[str]) -> None:
        self._role_row = role_row
        self._statements = statements

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, query: Any, params: Any = None) -> None:
        self._statements.append(query if isinstance(query, str) else query.as_string(None))

    def fetchone(self) -> tuple[bool, ...] | None:
        return self._role_row


class FakeConnection:
    """Stands in for an admin connection; records every statement issued."""

    def __init__(self, role_row: tuple[bool, ...] | None) -> None:
        self._role_row = role_row
        self.statements: list[str] = []

    def cursor(self) -> FakeCursor:
        return FakeCursor(self._role_row, self.statements)


def _matching(statements: list[str], prefix: str) -> list[str]:
    return [s for s in statements if s.lstrip().upper().startswith(prefix)]


def test_first_run_creates_a_least_privilege_login_role() -> None:
    conn = FakeConnection(role_row=None)

    _ensure_app_role(conn, "rag_app", "s3cret")  # type: ignore[arg-type]

    created = _matching(conn.statements, "CREATE ROLE")
    assert len(created) == 1
    for attribute in ("LOGIN", "NOSUPERUSER", "NOBYPASSRLS", "NOCREATEDB", "NOCREATEROLE"):
        assert attribute in created[0]
    assert '"rag_app"' in created[0]
    assert len(_matching(conn.statements, "GRANT")) == 3


def test_rerun_validates_the_existing_role_without_altering_it() -> None:
    conn = FakeConnection(role_row=LEAST_PRIVILEGE)

    _ensure_app_role(conn, "rag_app", "s3cret")  # type: ignore[arg-type]

    # ALTER ROLE ... NOSUPERUSER needs a superuser even to switch it off, so a
    # re-run under the RDS master user must never issue it.
    assert _matching(conn.statements, "ALTER ROLE") == []
    assert _matching(conn.statements, "CREATE ROLE") == []
    assert len(_matching(conn.statements, "GRANT")) == 3


@pytest.mark.parametrize(
    ("role_row", "attribute"),
    [
        ((True, False, False, False), "rolsuper"),
        ((False, True, False, False), "rolbypassrls"),
        ((False, False, True, False), "rolcreatedb"),
        ((False, False, False, True), "rolcreaterole"),
    ],
)
def test_overprivileged_existing_role_is_rejected_before_any_grant(
    role_row: tuple[bool, ...], attribute: str
) -> None:
    conn = FakeConnection(role_row=role_row)

    with pytest.raises(RuntimeRoleOverprivilegedError, match=attribute):
        _ensure_app_role(conn, "rag_app", "s3cret")  # type: ignore[arg-type]

    assert _matching(conn.statements, "GRANT") == []
    assert _matching(conn.statements, "ALTER ROLE") == []
    assert _matching(conn.statements, "CREATE ROLE") == []
