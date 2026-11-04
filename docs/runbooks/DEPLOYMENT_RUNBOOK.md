# Deployment Runbook

**Status: no environment running.** Local development uses `make dev`.
The dev AWS environment has been deployed with Terraform (M5/M6) and is
currently **costed down** (see below). Do not expose any deployment on a
network while ID-01 is open ([deployment gate](../security/M7_AI_SECURITY_EVIDENCE_INDEX.md#deployment-gate)).

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
3. **Remove the temporary `checkov:skip=CKV_AWS_293`** in
   `infrastructure/modules/rds/main.tf` and restore `deletion_protection =
   true` / `skip_final_snapshot = false` when RDS deletion protection is
   restored.
4. Rerun the DB bootstrap task (`make db-init` locally) and synthetic
   ingestion (`make ingest`).
5. ECR images and digests are preserved and should not need rebuilding.

## Planned production flow

1. PR merged to `main` with green CI (lint, types, tests, IaC scan, secrets scan).
2. Image built, Trivy-scanned, SBOM generated (CycloneDX), pushed to ECR (image signing not yet implemented).
3. Terraform plan reviewed; apply from a saved plan after approval (CI OIDC to AWS is a target, not implemented).
4. ECS deploy; health checks gate traffic shift.
5. Post-deploy: smoke test `POST /v1/query` against the golden dataset subset.

## Verification checklist

- `/healthz` returns 200 in the new task set
- CloudWatch dashboard shows traffic on the new deployment
- No 5xx or ECS task-health alarm firing (Bedrock Guardrails are not deployed)
