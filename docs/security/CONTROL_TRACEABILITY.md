# Security Control Traceability

Every row links a risk to the code that mitigates it and the test that
proves it. Rows are added only when implementation and verification exist -
planned controls live in the threat model and FAILURE_MODES.md, not here.

| Risk | Control | Implementation | Verification | Evidence |
|---|---|---|---|---|
| Cross-tenant data access | Tenant filter in the retrieval query | `app/rag/retrieval.py` | `app/tests/test_tenant_isolation.py` | CI run |
| Cross-tenant access after an application-layer regression | PostgreSQL row-level security, FORCEd, fail-closed when tenant unset | `app/rag/retrieval.py` (SCHEMA_SQL) | `app/tests/test_rls_integration.py` | CI integration job |
| Caller asserting tenant in the request body | Tenant resolved by the server-side resolver, never from the payload; `extra="forbid"` on request models. **Limitation (ID-01, open):** the resolver reads caller-supplied `X-Tenant-Id`/`X-Tenant-Role` headers validated against an allowlist, so identity is not verified | `app/auth/tenancy.py`, `app/models/requests.py` | `app/tests/test_tenant_isolation.py`; corpus ID-01 strict xfail | CI run |
| Over-broad data access by role | Classification filter derived from role, applied in SQL | `app/auth/permissions.py`, `app/rag/retrieval.py` | `app/tests/test_tenant_isolation.py` | CI run |
| Privilege escalation via direct model access | `/v1/generate` restricted to admin role | `app/api/routes/query.py` | `app/tests/test_tenant_isolation.py` | CI run |
| Write-up of unreadable data | Ingestion classification capped at the caller's read scope | `app/api/routes/documents.py` | `app/tests/test_tenant_isolation.py` | CI run |
| Row security bypassed by an over-privileged runtime role | Dedicated `NOSUPERUSER NOBYPASSRLS` runtime role; DDL confined to an admin connection; startup preflight refuses a bypass-capable role | `app/rag/schema.py`, `scripts/initialize_database.py` | `app/tests/test_rls_integration.py::test_runtime_role_cannot_bypass_row_security` | CI integration job |
| Cross-tenant write or update | RLS `WITH CHECK` and `USING` on INSERT/UPDATE | `app/rag/schema.py` (policy) | `test_rls_rejects_cross_tenant_write`, `test_rls_blocks_cross_tenant_update` | CI integration job |
| Over-broad access within a tenant | Per-document `allowed_roles` ACL applied in the retrieval query | `app/rag/retrieval.py` | `app/tests/test_tenant_isolation.py`, `app/tests/test_rls_integration.py` | CI run |
| Unauthorized content reaching the model prompt | Filtering happens at retrieval; the service adds nothing to context | `app/rag/service.py` | `app/tests/test_tenant_isolation.py` | CI run |
| Prompt injection (question or poisoned chunk) | Per-request unforgeable boundary framing of passages and question (M7.2); hidden-control normalization; system prompt treats both as data. Structural only - model behaviour is measured separately (M7.5) | `app/rag/prompting.py`, `app/core/security.py` | `app/tests/test_prompting.py`, `evaluations/tests/test_prompt_injection.py`, `evaluations/tests/test_adversarial_offline.py` (DPI/IPI enforced) | CI run |
| Unauthorized replacement of an existing document (AUTHZ-01) | Authorize against the existing document's classification and ACL, atomically, with serialized concurrent writers; keyword-only `authorize_as` with no default | `app/rag/retrieval.py`, `app/rag/ingestion.py`, `app/api/routes/documents.py` | `app/tests/test_rls_integration.py` (real PostgreSQL), `app/tests/test_tenant_isolation.py` | CI integration job; local real-PostgreSQL run at M7.7 |
| Sensitive values in model output (`/v1/query`) | Detector checked before citation processing: credentials/identifiers withheld, emails masked (M7.3). Does not cover the M7.5 S2 key family; `/v1/generate` output not checked | `app/rag/output_integrity.py`, `app/core/sensitive_data.py` | `app/tests/test_output_integrity.py`; corpus OUT-02 | CI run |
| Ungrounded answers / hallucination | No-context deterministic refusal without model call | `app/rag/service.py` | `evaluations/tests/test_groundedness.py` | CI run + scorecard |
| Fabricated citations | Citation indices validated against passages actually provided; invalid or uncited answers fail closed; only cited passages returned (M7.3) | `app/rag/output_integrity.py`, `app/rag/service.py` | `app/tests/test_output_integrity.py`, `evaluations/tests/test_response_quality.py`; corpus OUT-01 | CI run |
| Oversized input (cost/DoS) | Character limits before model invocation | `app/clients/bedrock.py`, `app/models/requests.py` | `app/tests/test_bedrock.py` | CI run |
| Hidden control characters | Input sanitization at API boundary | `app/core/security.py`, `app/api/routes/query.py` | `app/tests/test_security.py`, `app/tests/test_failure_modes.py` | CI run |
| Ungrounded fallback on store outage | Fail-closed 503; model never called | `app/api/routes/query.py` | `app/tests/test_failure_modes.py` | CI run |
| SQL injection via vectors | Parameterized queries; server-side vector cast | `app/rag/retrieval.py` | code review; no string-built SQL | repo |
| Committed secrets | TruffleHog and Gitleaks scans on every push/PR | `.github/workflows/security.yml` | workflow run | Actions log |
| IaC misconfiguration | Checkov scan, `soft_fail: false` | `.github/workflows/security.yml` | workflow run | Actions log |
| Dependency vulnerabilities | `pip-audit --require-hashes` against locked `uv.lock` | `.github/workflows/security.yml` | workflow run | Actions log |
| Container vulnerabilities | Blocking Trivy scan (`HIGH,CRITICAL`) with expiring allowlist | `.github/workflows/security.yml`, `.trivyignore.yaml` | workflow run | Actions log |
| Insecure Terraform declarations | Conftest / OPA policy-as-code gate | `policy/terraform/security.rego`, `.github/workflows/security.yml` | `policy/fixtures/` compliance tests | Actions log |
| Supply chain opacity | CycloneDX SBOMs for Python and container image | `.github/workflows/security.yml` | automated SBOM validation | GitHub Actions artifact |
| Untracked build artifacts | Docker image archive, SHA-256 digests, and build metadata | `.github/workflows/security.yml` | checksum verification | GitHub Actions artifact |
| Prompt/response data leakage via logs | Metadata-only structured logging by default | `app/core/logging.py` | `LOG_FULL_CONTENT` gate, code review | repo |
