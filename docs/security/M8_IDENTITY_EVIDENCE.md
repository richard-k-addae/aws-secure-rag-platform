# M8 Production Identity Hardening — Evidence

**ID-01 status: CLOSED at the verified Cognito/OIDC code boundary, real PostgreSQL RLS integration, and live Cognito token/JWKS compatibility.**
**Live Cognito verification (M8.5): PASS** (run `bae36d82`, cleanup verified). **Not deployed. Not production-ready.**

M8 replaces caller-controlled `X-Tenant-Id` / `X-Tenant-Role` headers with a
verified Amazon Cognito user pool **access token**. Tenant and role are derived
server-side from administrator-managed `cognito:groups`. This document records
what is proven, by which evidence, and what is not.

Branch `m8/production-identity-hardening` (base `722bb73`). Every row cites
evidence in the repository; nothing is inferred.

## What is and is not claimed

| Claim | Status |
|---|---|
| Implemented and tested locally (verifier, mapping, HTTP boundary, logging) | **Yes** |
| Validated against real PostgreSQL row-level security (verified token → trusted tenant → RLS) | **Yes** (local `pgvector/pgvector:pg16`; CI `integration-tests` job runs the same file) |
| Verified against live Amazon Cognito tokens and JWKS | **Yes** (M8.5 run `bae36d82`: PASS; temporary pool, users and IAM roles destroyed) |
| Deployed | **No.** The dev runtime is costed down and its image predates M8 (R16) |
| Production-ready | **No** (see "Deployment prerequisites") |

## Design

```
Authorization: Bearer <Cognito access token>
  -> structure/header checks (alg must be RS256; kid bounded; jku/x5u/x5c/jwk ignored)
  -> signing key from {OIDC_ISSUER}/.well-known/jwks.json only (cached, bounded refresh, failure backoff)
  -> RS256 signature, iss, exp/iat/nbf (leeway 30 s), required claims
  -> token_use == "access", client_id in OIDC_CLIENT_IDS
  -> cognito:groups: exactly one tenant:<id> (also in TENANT_ALLOWLIST) and exactly one role:<reader|ingestor|admin>
  -> TenantContext -> existing RBAC, classification/ACL filters and PostgreSQL RLS
```

Error contract: 401 `{"detail":"Not authenticated"}` with `WWW-Authenticate:
Bearer`; 403 `{"detail":"Forbidden"}` (identity mapping denied, unknown
tenant/role, action denied); 503 `{"detail":"Authentication unavailable"}`
when the key set is unreachable with no usable cache **or authentication is
not configured**. There is no development bypass: empty OIDC settings fail
closed.

Security events (bounded names only, never token material): `missing_token`,
`malformed_token`, `invalid_algorithm`, `invalid_signature`, `expired_token`,
`token_not_yet_valid`, `wrong_issuer`, `wrong_audience`, `wrong_client`,
`wrong_token_use`, `missing_claim`, `unknown_kid`, `invalid_token`,
`jwks_unavailable`, `auth_not_configured`, `identity_mapping_denied`, plus the
M6 `unknown_tenant` / `unknown_role`. `missing_tenant` was retired.

Dependency: `pyjwt[crypto]==2.15.1` (pinned; a tripwire test fails if the
PyJWT internals the cache-restore logic relies on change).

## Evidence index

| Item | Control | Status | Evidence | Tests |
|---|---|---|---|---|
| M8.1 | Token verification and JWKS handling | **ENFORCED (local)** | `app/auth/oidc.py` | `app/tests/test_oidc_verification.py` (55): AUTHN-01..12, algorithm/`kid`/header abuse, claims, audience, bounded refresh, rotation, outage backoff, unusable JWKS (non-JSON, invalid UTF-8, empty), cache restoration, production network path with no redirects |
| M8.2 | Fail-closed group mapping | **ENFORCED (local)** | `app/auth/tenancy.py` | `app/tests/test_identity_mapping.py` (18): duplicates, missing, empty, malformed claim, case variants, unknown tenant/role |
| M8.3 | Header authority removed; generic errors; no token logging | **ENFORCED (local)** | `app/auth/tenancy.py`, `app/core/telemetry.py` | `app/tests/test_identity_adversarial.py` (21): OpenAPI has no identity headers, AUTHZ-ID-01..05, AUTHN-11, LOG-01/02 with positive control; `app/tests/test_tenant_isolation.py` (18); corpus **ID-01 enforced**, ID-01C retired (`evaluations/security/adversarial_cases.json`, 21 cases, all enforced) |
| M8.4 | Verified token through real PostgreSQL RLS | **ENFORCED (real PostgreSQL)** | `app/tests/test_rls_integration.py` | 58 tests (25 pre-M8 + 33 M8.4): RLS-ID-00 policy active and missing tenant context exposes 0 rows; RLS-ID-01..06 verified reads, forged headers, cross-tenant document IDs, reader/ingestor/admin, 9 invalid-token kinds and 8 unmappable identities never reach the database, interleaved and concurrent requests, transaction-scoped tenant binding on a reused connection, per-operation connections closed |
| M8.4 control | Negative control | Recorded | — | With RLS disabled on the disposable table, 10 tests failed (including RLS-ID-00 and RLS-ID-06c); with `BYPASSRLS` on the runtime role, bootstrap refused to provision |
| M8.5 | Live Cognito validation | **PASS (live)** | `evaluations/security/m8_5_live_cognito.json`; `evaluations/live/m8_5_cognito.py`, `scripts/validate_live_cognito.py`, `evaluations/live/terraform_runner.py`, `scripts/identity_eval_terraform.py`, `evaluations/live/aws_identity.py`, `infrastructure/environments/identity-eval/`, `infrastructure/environments/identity-eval-bootstrap/` | Live run `bae36d82`: 18 cases, 14 PASS, 1 NOT_TESTABLE (R-14), 1 SKIPPED (R-15), 2 LIMITATION_CONFIRMED (R-16, R-17); cleanup verified. Offline: `evaluations/tests/test_live_cognito_harness.py` (54), `evaluations/tests/test_identity_eval_terraform.py` (329); mutation controls (dropped `client_id` check, widened allowlist) failed R-06 / R-08 |
| M8.6 | Operational configuration | **CONFIGURED in source (not applied)** | `infrastructure/modules/ecs/*`, `infrastructure/environments/dev/{main,variables,identity,dashboard}.tf` | `app/tests/test_m8_operational_config.py`: dashboard/alarm events are registered events, ECS receives validated `TENANT_ALLOWLIST`/`OIDC_ISSUER`/`OIDC_CLIENT_IDS`, fail-closed defaults, no bypass setting |

Review finding fixed before merge: PyJWT's network fetch does not wrap a
non-JSON key-set body, which escaped as HTTP 500 and bypassed the failure
backoff. `TrustedJwksClient.fetch_data` now maps any unusable response to 503,
starts the backoff and restores the last good key set; the three
production-path tests fail without the fix.

## Live Cognito verification (M8.5) — PASS

Evidence: `evaluations/security/m8_5_live_cognito.json` (run `bae36d82`,
`overall` PASS, `run_status` completed, `cleanup.verified` true). The production
verifier (`app.auth.oidc.build_oidc_verifier`) ran against a temporary, isolated
`identity-eval` user pool. That pool was created through reviewed Terraform plans by
the temporary, MFA-only role `rag-eval-terraform`; the harness ran as
`rag-eval-harness` (`infrastructure/environments/identity-eval-bootstrap/`).

| Result | Cases |
|---|---|
| PASS (14) | R-01 issuer discovery, R-02 real JWKS shape, R-03 valid access token, R-04 role and tenant from real groups, R-05 ID token rejected, R-06 non-allowlisted client, R-07 tampered tokens, R-08 missing/ambiguous groups, R-09 wrong issuer with a valid key set, R-10 expired token, R-11 JWKS cache, R-12 bounded unknown-`kid` refresh, R-13 JWKS endpoint unavailable (503), R-18 no token or secret material in logs |
| NOT_TESTABLE (1) | R-14 signing-key rotation cannot be triggered on a Cognito pool; covered offline by `app/tests/test_oidc_verification.py` |
| SKIPPED (1) | R-15 optional live token through PostgreSQL RLS (no database URL supplied); real RLS integration is proven separately by M8.4 |
| LIMITATION_CONFIRMED (2) | R-16 group removed mid-session and R-17 global sign-out: an issued access token stays valid until expiry (R15 below) |

Cleanup: all 10 synthetic users were deleted and the deletions verified. The
evaluation pool was then destroyed (an independent `describe-user-pool` returned
`ResourceNotFoundException`), and the temporary IAM bootstrap roles and policies
were destroyed (0 added, 0 changed, 4 destroyed).

Still not verified: the network path from a deployed ECS task to the JWKS
endpoint (prerequisite 1) and any production user pool (prerequisite 3).

## Deployment prerequisites (open)

Determined from the Terraform source; nothing in the application stack was
provisioned for M8. (The temporary M8.5 Cognito evaluation resources and
bootstrap IAM roles were provisioned, exercised and destroyed separately; see
"Live Cognito verification (M8.5)" above.)

1. **JWKS network path (R14, blocker).** ECS tasks run in private subnets
   with no NAT gateway (`infrastructure/modules/networking/main.tf`: only the
   public route table has a default route). Task egress is limited to HTTPS to
   the interface endpoints `ecr.api`, `ecr.dkr`, `logs`, `bedrock-runtime`,
   `secretsmanager` and the S3 gateway prefix list
   (`infrastructure/modules/security/main.tf`). There is **no path** to
   `https://cognito-idp.<region>.amazonaws.com/<pool>/.well-known/jwks.json`;
   a deployed M8 task would answer 503 on every protected route. A
   `cognito-idp` interface endpoint **must not be assumed** to serve the JWKS
   path; it needs validation. Alternatives: NAT with restricted HTTPS egress,
   or configured static keys (a code change that gives up automatic rotation).
2. **New application image (R16, blocker).** The pinned dev digests
   (`sha256:05c5…`, commit `1194012`) predate M8 and trust headers.
3. **Approved production identity provider (R1).** No production user pool
   exists. The `identity-eval` pool was temporary, has been destroyed, and must
   never be referenced by the application stack.
4. **Valid OIDC configuration.** Set `oidc_issuer` and `oidc_client_ids`
   (validated: Cognito issuer in a matching region, alphanumeric client IDs;
   `tenant_allowlist` lowercase IDs). Empty values fail closed (503). The
   Terraform `check "identity_configuration"` only **warns**; it is not an
   enforcement gate.
5. Remaining gate items in the
   [M7 register](M7_AI_SECURITY_EVIDENCE_INDEX.md#deployment-gate): R2, R7,
   R9, plus TLS ingress (the ALB phase is deferred). R8 is closed: CI was green on
   the PR #49 merge to `main` (`5d9475a`).

## Residual risks introduced or restated by M8

| # | Risk | Status |
|---|---|---|
| R1 | No production identity provider (live Cognito compatibility verified in M8.5) | Open |
| R14 | No JWKS network path from ECS tasks | Open; deployment blocker |
| R15 | Stateless verification: revocation and group removal effective only at token expiry | Open; short token lifetimes |
| R16 | Dev image digests predate M8 | Open; deployment blocker |
| R17 | Management-account placement and long-lived administrator credentials (with R10) | Open; acknowledged |
| R8 | CI on the M8 changes | Closed: CI, Security and Terraform green on the PR #49 merge to `main` (`5d9475a`) |

## Verification performed for M8.6

See the M8.6 closure report: full pytest with and without PostgreSQL, the
real-PostgreSQL suite, `run_evaluations.py`, ruff, mypy, Terraform
fmt/validate, Checkov, Trivy, gitleaks and TruffleHog on added content, and
`git diff --check`. No AWS API was called for M8.6.
