# Security Findings

Defects found in this platform's own controls, with the fix and the
regression test that keeps them fixed. Recorded because a control that was
never adversarially tested is a claim, not a control.

M7 AI-security findings (AUTHZ-01, IPI structural findings, citation
integrity, the S2 sensitive-output detector gap, ID-01 and the Guardrail
evaluations) are tracked in the
[M7 finding register](M7_AI_SECURITY_EVIDENCE_INDEX.md#m7-finding-register).

---

## F-001 — Row-level security was silently inert; a false-passing test hid it

**Severity:** High (defense-in-depth layer absent, and the test suite
reported it as present)
**Status:** Fixed
**Found:** Milestone 2, first real execution of the integration suite against
PostgreSQL

### What happened

The `tenant_isolation` row-security policy was correct, and
`ALTER TABLE ... FORCE ROW LEVEL SECURITY` was in place. Row security was
nonetheless not enforced at all.

Two independent causes:

1. **The runtime connection was a superuser.** The development and CI
   databases were provisioned with `POSTGRES_USER=rag`, which creates a
   superuser, and the application connected as that role. PostgreSQL exempts
   superusers and roles holding `BYPASSRLS` from row-level security
   *unconditionally*. `FORCE ROW LEVEL SECURITY` removes only the
   **table-owner** exemption — it has no effect on the superuser exemption.
   The policy was therefore never evaluated.

2. **A test asserted the wrong thing and passed.**
   `test_rls_rejects_cross_tenant_write` performed an INSERT that omitted
   `document_id`, a `NOT NULL` column, and asserted only
   `pytest.raises(psycopg.errors.Error)`. The statement failed on the
   constraint, never reaching policy evaluation, and the test reported
   success. It would have passed with row security switched off entirely.

The four other integration tests passed on the strength of the
application-layer `WHERE` clause alone, so the missing database layer
produced no visible symptom. Only the two tests that queried *without* a
tenant predicate — precisely the ones written to isolate the database layer —
failed and exposed it.

### Fix

- Privilege separation. `app/rag/schema.py` performs all DDL, policy
  creation and role provisioning under an **administrative** connection
  (`ADMIN_DATABASE_URL`) and creates a dedicated runtime login role
  `NOSUPERUSER NOBYPASSRLS`, granted only DML on `document_chunks`. The
  application (`DATABASE_URL`) never connects with administrative rights.
- `assert_no_rls_bypass()` reads `rolsuper` and `rolbypassrls` for the
  connecting role. `scripts/initialize_database.py` calls it as a preflight
  and exits non-zero if either is true, so a misprovisioned environment fails
  at setup rather than silently losing a security layer.
- The cross-tenant INSERT test now supplies every `NOT NULL` column, so the
  policy is the only thing that can reject it, and asserts
  `psycopg.errors.InsufficientPrivilege` (SQLSTATE 42501) plus the
  `row-level security` message text.
- Added `test_runtime_role_cannot_bypass_row_security` and
  `test_runtime_role_is_not_the_table_owner` as explicit preconditions, so
  the environment assumption every other row-security test depends on is
  itself asserted.
- Added `test_rls_blocks_cross_tenant_update` — the original suite covered
  read and insert but not update.

### Lessons applied

- A negative test must fail for exactly one reason. Asserting a broad
  exception class lets an unrelated failure impersonate the control.
- Environment provisioning is part of the control. A correct policy under the
  wrong role is no policy.
- Two layers claimed, one layer tested: the application filter masked the
  absent database layer. Layer-specific tests must bypass the layer above
  them — which is why these tests query without a tenant predicate.
