# Deployment Runbook

**Status: no environment running.** Local development uses `make dev`.
The dev AWS environment has been deployed with Terraform (M5/M6) and is
currently **costed down** (see below). Do not expose any deployment on a
network until the M8 identity prerequisites below and the
[deployment gate](../security/M7_AI_SECURITY_EVIDENCE_INDEX.md#deployment-gate)
are met. M8 closed ID-01 in code; it has **not** been verified against live
Cognito or deployed.

## Current dev environment status (costed down 2026-11-03)

The dev runtime was intentionally destroyed with a reviewed, saved,
targeted Terraform destroy plan to stop ongoing cost.

| Item | State |
|---|---|
| RDS PostgreSQL (`rag-platform-dev-postgres`) | Destroyed (no final snapshot; data is synthetic and re-creatable) |
| ECS cluster/service, Fargate task | Destroyed (app task definition revision 5 remains registered via `skip_destroy`) |
| VPC, subnets, routes, VPC interface/gateway endpoints | Destroyed |
| Runtime log groups, dashboard, alarms, runtime secret, runtime KMS keys | Destroyed (secret and KMS keys entered their 30-day recovery/deletion windows) |
| ECR repositories (`aws-secure-rag-platform`, `rag-platform-adot`) and their KMS keys | **Preserved**, with all image digests |
| Terraform backend (`rag-platform-tfstate-376129869231`, `dev/terraform.tfstate`, S3 lockfile, versioning) | **Preserved** |

Recreating the environment:

1. `terraform plan` from `infrastructure/environments/dev` proposes
   recreating the destroyed resources; review and apply it as a saved plan.
2. If within 30 days of the cost-down, restore or force-delete the pending
   runtime secret `rag-platform-dev/db/rag-app-runtime` before Terraform can
   reuse its name.
3. RDS deletion safety is already restored in source
   (`deletion_protection = true`, `skip_final_snapshot = false`; the
   temporary `checkov:skip=CKV_AWS_293` was removed during final repository
   pre-closure), so a recreated instance is protected. A future teardown
   must again disable deletion protection through a reviewed change.
4. Rerun the DB bootstrap task (`make db-init` locally) and synthetic
   ingestion (`make ingest`).
5. ECR images and digests are preserved, **but the pinned app and
   bootstrap digests (`sha256:05c5…`, commit `1194012`) predate M8 and
   trust caller identity headers.** Do not recreate the service with them:
   build, scan and pin a new image from the merged M8 code first (R16).

## M8 identity deployment prerequisites (open)

Determined from the Terraform source on 2026-11-05; nothing was provisioned.

| # | Prerequisite | Current state | Evidence |
|---|---|---|---|
| 1 | **JWKS network path** (R14, blocker) | **Missing.** Private subnets have no NAT gateway and no default route; task egress allows only HTTPS to the `ecr.api`, `ecr.dkr`, `logs`, `bedrock-runtime` and `secretsmanager` interface endpoints and the S3 gateway prefix list. The Cognito JWKS endpoint (`https://cognito-idp.<region>.amazonaws.com/<pool>/.well-known/jwks.json`) is unreachable, so every protected route would return 503 | `infrastructure/modules/networking/main.tf`, `infrastructure/modules/security/main.tf` |
| 2 | Supported route to JWKS | Undecided. A `cognito-idp` interface VPC endpoint must **not** be assumed to serve the JWKS path until validated; alternatives are a NAT gateway with HTTPS egress restricted as far as possible, or configured static keys (a code change that gives up automatic key rotation) | Needs a reviewed design and approval |
| 3 | **New application image** (R16, blocker) | Pinned digests predate M8 | `infrastructure/environments/dev/variables.tf` (`app_image_digest`, `db_bootstrap_image_digest`) |
| 4 | **Approved production identity provider** (R1) | None. The `identity-eval` pool is temporary and must never be referenced by this stack | `infrastructure/environments/identity-eval/` |
| 5 | Live identity verification (R1) | Not executed (M8.5 harness ready; needs separately approved role sessions) | [M8 evidence](../security/M8_IDENTITY_EVIDENCE.md) |
| 6 | **Valid OIDC configuration** before enabling protected routes | Wired, empty by default: `oidc_issuer`, `oidc_client_ids`, `tenant_allowlist` pass to the task as `OIDC_ISSUER`, `OIDC_CLIENT_IDS`, `TENANT_ALLOWLIST` with input validation. Empty OIDC values fail closed (503 on protected routes; `/healthz` stays 200) | `infrastructure/modules/ecs/`, `infrastructure/environments/dev/variables.tf` |

The `check "identity_configuration"` block in
`infrastructure/environments/dev/identity.tf` only prints a **warning** in
plan/apply output when the OIDC values are empty or the issuer is outside the
deployment region. It is not an enforcement gate; the prerequisites above
are.

Access tokens are verified statelessly: a revoked token or removed group
stays effective until the access token expires (R15). Keep production
access-token lifetimes short.

## Open infrastructure cleanup

- **Unused ALB security group** (`aws_security_group.alb` in
  `infrastructure/modules/security/main.tf`, with its `alb_to_ecs` and
  `ecs_from_alb` rules): kept from the deferred ALB/TLS phase, attached to
  nothing, no public ingress. Classified **REMEDIATE** (Checkov CKV2_AWS_5
  skip marked open); remove in a later reviewed infrastructure change, or
  re-decide, by 2026-12-04.

## Planned production flow

1. PR merged to `main` with green CI (lint, types, tests, IaC scan, secrets scan).
2. Image built from the merged M8 code, Trivy-scanned, SBOM generated (CycloneDX), pushed to ECR and its digest pinned (image signing not yet implemented).
3. Terraform plan reviewed; apply from a saved plan after approval (CI OIDC to AWS is a target, not implemented).
4. ECS deploy; health checks gate traffic shift.
5. Post-deploy: smoke test `POST /v1/query` with a valid access token from the approved identity provider (expect 200), without a token (expect 401) and against the golden dataset subset; a 503 "Authentication unavailable" means OIDC configuration or the JWKS path is missing.

## Verification checklist

- `/healthz` returns 200 in the new task set
- CloudWatch dashboard shows traffic on the new deployment
- No 5xx or ECS task-health alarm firing (Bedrock Guardrails are not deployed)
