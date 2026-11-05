# M8 Production Identity Hardening — Evidence

**ID-01 status: ENFORCED at the code and PostgreSQL integration-test level.**
**Real Cognito verification: NOT EXECUTED.** **Not deployed. Not production-ready.**

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
| Verified against live Amazon Cognito tokens and JWKS | **NOT EXECUTED** |
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
| M8.5 | Live Cognito validation harness | **READY; NOT EXECUTED** | `evaluations/live/m8_5_cognito.py`, `scripts/validate_live_cognito.py`, `evaluations/live/terraform_runner.py`, `scripts/identity_eval_terraform.py`, `evaluations/live/aws_identity.py`, `infrastructure/environments/identity-eval/` | Offline only: `evaluations/tests/test_live_cognito_harness.py` (54), `evaluations/tests/test_identity_eval_terraform.py` (329). Matrix R-01..R-18 against fake Cognito with synthetic keys; mutation controls (dropped `client_id` check, widened allowlist) failed R-06 / R-08 |
| M8.6 | Operational configuration | **CONFIGURED in source (not applied)** | `infrastructure/modules/ecs/*`, `infrastructure/environments/dev/{main,variables,identity,dashboard}.tf` | `app/tests/test_m8_operational_config.py`: dashboard/alarm events are registered events, ECS receives validated `TENANT_ALLOWLIST`/`OIDC_ISSUER`/`OIDC_CLIENT_IDS`, fail-closed defaults, no bypass setting |

Review finding fixed before merge: PyJWT's network fetch does not wrap a
non-JSON key-set body, which escaped as HTTP 500 and bypassed the failure
backoff. `TrustedJwksClient.fetch_data` now maps any unusable response to 503,
starts the backoff and restores the last good key set; the three
production-path tests fail without the fix.

## Real Cognito verification — NOT EXECUTED

The M8.5 matrix (discovery, real JWKS shape, valid access token, ID token
rejection, wrong client, tampering, group mapping, wrong issuer vs JWKS
unavailability, expiry, cache, unknown `kid`, revocation/group-change
limitations, log hygiene) has run **only against fakes**. Steps completed:
read-only AWS preflight and a reviewed Terraform plan for the temporary
`identity-eval` pool (9 creates, 0 changes). **Nothing was applied; no pool,
client, group or user exists; no live token was issued.** The live run now
requires dedicated role sessions (`rag-eval-terraform`, `rag-eval-harness`)
that do not exist yet and need separate IAM approval.

Not verified until a live run passes: real access-token claim shape, real
JWKS retrieval, Cognito acceptance of `tenant:` / `role:` group names, ID-token
rejection reason on real tokens, and the revocation/group-change window.

## Deployment prerequisites (open)

Determined from the Terraform source; nothing was provisioned.

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
   exists; the `identity-eval` pool is temporary and must never be referenced
   by the application stack.
4. **Valid OIDC configuration.** Set `oidc_issuer` and `oidc_client_ids`
   (validated: Cognito issuer in a matching region, alphanumeric client IDs;
   `tenant_allowlist` lowercase IDs). Empty values fail closed (503). The
   Terraform `check "identity_configuration"` only **warns**; it is not an
   enforcement gate.
5. Remaining gate items in the
   [M7 register](M7_AI_SECURITY_EVIDENCE_INDEX.md#deployment-gate): R8 (green
   CI on this branch), R2, R7, R9, plus TLS ingress (the ALB phase is deferred).

## Residual risks introduced or restated by M8

| # | Risk | Status |
|---|---|---|
| R1 | Real Cognito verification not executed; no production identity provider | Open |
| R14 | No JWKS network path from ECS tasks | Open; deployment blocker |
| R15 | Stateless verification: revocation and group removal effective only at token expiry | Open; short token lifetimes |
| R16 | Dev image digests predate M8 | Open; deployment blocker |
| R17 | Management-account placement and long-lived administrator credentials (with R10) | Open; acknowledged |
| R8 | CI has not run on this branch | Open until a successful CI run |

## Verification performed for M8.6

See the M8.6 closure report: full pytest with and without PostgreSQL, the
real-PostgreSQL suite, `run_evaluations.py`, ruff, mypy, Terraform
fmt/validate, Checkov, Trivy, gitleaks and TruffleHog on added content, and
`git diff --check`. No AWS API was called for M8.6.
