# Failure-Mode Contract

Required behavior under failure. Each implemented row is enforced by a test;
rows marked Planned land with the milestone shown and must arrive with tests.

| Failure | Required behavior | Status | Verification |
|---|---|---|---|
| Vector store unavailable | 503, refuse; never call the model | Implemented | `app/tests/test_failure_modes.py` |
| No qualifying chunks | Deterministic refusal; no model call, no model memory | Implemented | `evaluations/tests/test_groundedness.py` |
| Bedrock throttled | Controlled 503 with `Retry-After` | Implemented | `app/tests/test_failure_modes.py` |
| Oversized input | 413 before any model call | Implemented | `app/tests/test_bedrock.py`, `app/tests/test_query.py` |
| Control characters in input | Stripped before processing | Implemented | `app/tests/test_failure_modes.py` |
| Tenant context missing | 401 | Implemented | `app/tests/test_tenant_isolation.py` |
| Unknown tenant or role | 403 | Implemented | `app/tests/test_tenant_isolation.py` |
| Caller asserts its own tenant in the payload | 422; identity always resolved server-side | Implemented | `app/tests/test_tenant_isolation.py` |
| Tenant unset on a database connection | RLS matches no rows (fail closed) | Implemented | `app/tests/test_rls_integration.py` (CI) |
| Cross-tenant write attempt | Rejected by RLS `WITH CHECK` | Implemented | `app/tests/test_rls_integration.py` (CI) |
| Runtime database role can bypass row security | Initialization fails with a non-zero exit; service not started | Implemented | `scripts/initialize_database.py`, `test_runtime_role_cannot_bypass_row_security` |
| Cross-tenant UPDATE attempt | Zero rows affected; target row unchanged | Implemented | `test_rls_blocks_cross_tenant_update` (CI) |
| Role absent from a document's `allowed_roles` | Chunk not retrieved; no signal it exists | Implemented | `app/tests/test_tenant_isolation.py`, `app/tests/test_rls_integration.py` (CI) |
| Ingestion above the caller's classification | 403 | Implemented | `app/tests/test_tenant_isolation.py` |
| Unknown classification value | 422 from schema validation | Implemented | request model enum |
| Duplicate ingestion event | Idempotent processing | Planned (M6) | with SQS pipeline |
| Guardrail layer error | **Profile-dependent**: `prod` fails closed; `dev`/`test` degrade with an explicit warning and structured log event | Not applicable - Guardrails evaluated in M7.6 and not adopted ([ADR 0005](../adr/0005-do-not-adopt-bedrock-guardrails.md)); this contract applies if a Guardrail layer is adopted later | - |
