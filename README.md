# AWS Secure RAG Platform

> Security-first Retrieval-Augmented Generation platform on Amazon Bedrock, built with FastAPI, ECS Fargate, PostgreSQL/pgvector, Terraform, DevSecOps controls, observability, adversarial AI-security testing and verified caller identity.

**Project status: engineering and AI-security portfolio scope complete through M8; not production-ready.** M8 replaced caller-supplied identity headers with verified Amazon Cognito access tokens (ID-01): implemented and tested locally, and validated against real PostgreSQL row-level security. It has **not been verified against live Amazon Cognito** and is **not deployed**; the AWS dev runtime is intentionally costed down. See [Deployment readiness](#deployment-readiness).

## Overview

A multi-tenant RAG service that answers questions only from documents the caller is authorized to read, cites the passages it used, and fails closed when it cannot. It is a platform-engineering and AI-security project, not a chatbot demo:

- **Verified identity** — every `/v1` request needs a Cognito user pool access token; the service verifies it (RS256 signature, issuer, expiry, `token_use`, app client) and derives tenant and role only from administrator-managed `cognito:groups`. Request headers, query string and body carry no identity authority.
- **Authorization at retrieval time** — tenant, classification and per-document ACL filters in SQL, enforced again by PostgreSQL row-level security under a role that cannot bypass it.
- **Untrusted context handled structurally** — retrieved passages and the caller's question are framed with per-request random boundaries the content cannot forge; answers are checked for valid citations and sensitive output before they are returned.
- **Measured, not assumed** — a deterministic adversarial corpus gates CI, and live Bedrock runs measure model behavior with and without Bedrock Guardrails.
- **Delivered on AWS** — Terraform-built private networking, ECS Fargate, RDS PostgreSQL/pgvector, KMS, Secrets Manager and CloudWatch/OpenTelemetry observability, deployed live (M5/M6) and later deliberately costed down.

All data is synthetic. Governance mappings are alignment exercises, not certifications. Known gaps are documented rather than hidden.

## Evidence levels

| Claim | Status |
|---|---|
| ID-01 verified-identity code (token verification, group mapping, HTTP boundary, no token logging) | **ID-01 enforced and tested locally** |
| Verified tenant reaching PostgreSQL row-level security | **Verified against real PostgreSQL RLS** (local `pgvector/pgvector:pg16`; CI `integration-tests` job: CI validation pending) |
| Compatibility with real Cognito tokens and JWKS | **Live Cognito compatibility not verified** — the live validation harness exists but has not been run |
| JWKS network access from ECS | **Remains a deployment blocker** — private subnets have no path to Cognito's signing keys |
| Running deployment of the M8 code | **Not deployed** — the dev runtime is costed down, and the **pre-M8 image digests require replacement** |
| Production readiness | **Not production-ready** — see [Deployment readiness](#deployment-readiness) |

## Final validation

- **M1–M7** were merged to `main` through PR #48 (merge commit `722bb73`) after all pull-request checks passed; post-merge CI, Security and Terraform workflows on `main` also passed.
- **M8** (verified identity): CI validation pending. Local validation before the PR: full suite with PostgreSQL 794 passed; without PostgreSQL 736 passed and 58 skipped (all 58 are the PostgreSQL suite, which runs in its own CI job); adversarial corpus 21/21 enforced; ruff, mypy, Checkov, Trivy, Terraform validate, Gitleaks and TruffleHog clean.
- **M7.5 / M7.6:** live Bedrock adversarial baseline (54 calls, no Guardrails) and Guardrails comparison — bounded observations, not guarantees.

Project completion does not imply production readiness.

## Verified project evidence

| Area | Evidence |
|---|---|
| Verified identity (M8) | [M8 identity evidence](docs/security/M8_IDENTITY_EVIDENCE.md) — what is enforced, what is not verified, deployment prerequisites |
| AI security (M7) | [M7 evidence index](docs/security/M7_AI_SECURITY_EVIDENCE_INDEX.md) — finding register, scorecard, residual risks, deployment gate |
| Live model evaluation | [M7.5 live adversarial baseline](docs/security/M7_5_LIVE_ADVERSARIAL_BASELINE.md), [M7.6 Guardrails comparison](docs/security/M7_6_GUARDRAILS_COMPARISON.md) |
| Observability (M6) | [Milestone 6 evidence](docs/observability/M6_OBSERVABILITY_EVIDENCE.md), [M6 evidence index](docs/observability/M6_EVIDENCE_INDEX.md) |
| Supply chain (M4) | [Milestone 4 evidence](docs/security/MILESTONE_4_EVIDENCE.md), [patched ADOT build](docs/security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md) |
| Controls and findings | [Control traceability](docs/security/CONTROL_TRACEABILITY.md), [failure-mode contract](docs/security/FAILURE_MODES.md), [findings](docs/security/FINDINGS.md) |
| Deployment and cost-down | [Deployment runbook](docs/runbooks/DEPLOYMENT_RUNBOOK.md) |

### Early milestone screenshots

Historical: these document the project's initial CI and offline-evaluation foundation (Milestone 1), not its current state.

![Milestone 1 CI checks](docs/images/milestone-1-ci-checks.png)

![Offline AI evaluation gate](docs/images/offline-evaluation-gate.png)

## Implemented architecture

Built with Terraform, deployed live to an AWS dev account (M5/M6), verified, and later destroyed through a reviewed saved-plan procedure. **The runtime is intentionally costed down and not running**; ECR images and Terraform state are preserved, but the preserved image predates M8 and must be rebuilt before any redeployment.

```
GitHub Actions (validation only: tests, scanners, policy, Terraform validate)

Operator workstation -- Terraform (reviewed saved plans, S3 remote state)
  |
AWS dev account
  +-- VPC: private subnets, no public task IPs, no NAT, encrypted VPC flow logs
  |     +-- VPC endpoints: Bedrock runtime, ECR, CloudWatch Logs,
  |                        Secrets Manager, S3 (gateway)
  +-- ECS Fargate: FastAPI RAG service + ADOT (OpenTelemetry) collector sidecar
  |     +-- verifies Cognito access tokens in-process (M8; OIDC settings wired,
  |         empty by default = fail closed; no JWKS network path yet)
  +-- Amazon Bedrock
  |     +-- generation: Claude Sonnet 4.6 via US cross-Region inference profile
  |     +-- embeddings: Amazon Titan Text Embeddings v2
  +-- RDS PostgreSQL + pgvector (private, encrypted, RLS)
  +-- ECR (KMS-encrypted, immutable tags, digest-pinned images)
  +-- KMS customer-managed keys + Secrets Manager
  +-- CloudWatch: structured logs, EMF metrics, dashboard, alarms
```

Locally, the same service runs with Docker Compose (API + PostgreSQL/pgvector), with an optional OpenTelemetry Collector, Prometheus and Grafana stack.

**pgvector vs. OpenSearch Serverless:** pgvector provides embeddings search, metadata filtering, private connectivity, encryption and backups without OpenSearch Serverless's always-on cost floor. OpenSearch Serverless is the better fit for high-ingest, hybrid lexical+vector or Bedrock Knowledge Base workloads ([decision](docs/architecture/VECTOR_STORE_DECISION.md)).

### Future production architecture

Not implemented — production hardening that would be required beyond this project:

- An approved production identity provider (Cognito user pool or equivalent), validated live, and a supported network path from the service to its signing keys (JWKS)
- Managed ingress such as API Gateway or an ALB with TLS, plus AWS WAF
- Per-identity rate limiting and quotas
- Queue-based ingestion (e.g. SQS with a dead-letter queue)
- Broader sensitive-data controls (the S2 detector gap, request input, `/v1/generate` output)
- Container image signing and signed provenance; CI deployment through OIDC; operator access through short-lived role credentials in a dedicated account

## Security engineering highlights

- **Identity (M8):** Cognito access-token verification with fixed RS256, trusted issuer-derived JWKS (no redirects, `jku`/`x5u`/`jwk` ignored), bounded key refresh and failure backoff; exactly one `tenant:<id>` and one `role:<role>` group or 403; generic 401/403/503 responses; only bounded reason codes logged, never tokens
- **Authorization:** tenant, classification and per-document ACL filters in SQL plus PostgreSQL RLS (`NOSUPERUSER NOBYPASSRLS` runtime role asserted, not assumed); document replacement authorized against the *existing* stored classification and ACL, atomically, with serialized concurrent writers (AUTHZ-01)
- **Prompt boundaries:** per-request CSPRNG boundary tokens, untrusted-context framing, Unicode/control-character sanitization, JSON-encoded source metadata
- **Output integrity:** citations validated against the passages actually supplied; invalid or uncited answers fail closed; sensitive output withheld or redacted before return
- **Adversarial testing:** 21-case deterministic corpus in CI, all enforced (OWASP LLM 2025 and MITRE ATLAS tagged); pre-registered live Bedrock evaluations
- **Guardrails:** Bedrock Guardrails comparatively tested and **not adopted** on the evidence ([ADR 0005](docs/adr/0005-do-not-adopt-bedrock-guardrails.md))
- **Supply chain and IaC:** Checkov, Conftest/OPA, Trivy, pip-audit with hash-locked dependencies, Gitleaks, TruffleHog, CycloneDX SBOMs, build digests and metadata; dated, reviewed exceptions only
- **Infrastructure:** private networking with VPC endpoints, KMS customer-managed keys, Secrets Manager, least-privilege task roles, Terraform saved-plan review
- **Observability:** OpenTelemetry instrumentation with sanitized telemetry, ADOT, CloudWatch metrics, dashboard and alarms, including identity security events
- **Not delivered:** container image signing and signed provenance remain future work

## What this project demonstrates

- **Cloud engineering:** AWS VPC design with endpoints, ECS Fargate, RDS, IAM, KMS, Secrets Manager, ECR
- **DevSecOps:** Terraform with remote state, GitHub Actions, policy-as-code, supply-chain and security gates, exception governance
- **AI engineering:** RAG on Bedrock, embeddings, pgvector similarity search, grounded and cited answering
- **AI security:** direct and indirect prompt injection, authorization boundaries, verified identity, sensitive-output controls, citation integrity, adversarial evaluation, Guardrail evaluation
- **Observability:** OpenTelemetry, ADOT, CloudWatch dashboards and alarms, local Prometheus/Grafana

## Quickstart (local development)

Requires Docker, Python 3.11 with [uv](https://docs.astral.sh/uv/) (for the host-side setup commands), and AWS credentials with access to the configured Bedrock generation and embedding models.

```bash
uv sync --extra dev    # local Python environment for setup scripts and checks
cp .env.example .env   # set BEDROCK_MODEL_ID, EMBEDDING_MODEL_ID and AWS_REGION
make dev               # api + postgres/pgvector via docker compose
make db-init           # extension, table, indexes, RLS policy, runtime role
make ingest            # embed and load the synthetic corpus
curl localhost:8000/healthz
```

**Calling the API requires a verified identity; there is no development bypass.** Every `/v1` route needs `Authorization: Bearer <access token>` from an Amazon Cognito user pool you control:

- Set `OIDC_ISSUER` (`https://cognito-idp.<region>.amazonaws.com/<user-pool-id>`) and `OIDC_CLIENT_IDS` (your app client ID) in `.env`, and keep `TENANT_ALLOWLIST` consistent with your groups.
- In that pool, put each test user in exactly one `tenant:<id>` group (for example `tenant:tenant-a`, matching `TENANT_ALLOWLIST`) and exactly one `role:reader`, `role:ingestor` or `role:admin` group.
- Use the user's **access token** (ID tokens are rejected). The API container needs outbound HTTPS to Cognito to fetch signing keys.

```bash
curl -X POST localhost:8000/v1/query \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"question": "What is the document retention period?"}'
```

Expected failure responses: with `OIDC_ISSUER` or `OIDC_CLIENT_IDS` unset, protected routes return **503** `Authentication unavailable` (fail closed); without a valid token, **401**; with a valid token whose groups do not map to exactly one allowed tenant and one role, **403**. Never paste real tokens into issues, logs or commits.

Without a Cognito pool, the identity behavior is exercised by the test suite, which signs synthetic tokens with keys generated at test time (`app/tests/identity.py`).

Optional local observability (OpenTelemetry Collector, Prometheus, Grafana):

```bash
docker compose -f docker-compose.yml -f docker-compose.observability.yml up --build
```

Run checks:

```bash
make lint    # ruff + mypy
make test    # pytest (PostgreSQL row-security tests skip unless TEST_ADMIN_DATABASE_URL and TEST_DATABASE_URL are set)
make evals   # offline evaluation scorecard
```

## Repository structure

```
app/              FastAPI service: routes, RAG core, clients, auth (OIDC verification, tenancy), telemetry, tests
infrastructure/   Terraform modules (networking, security, ecs, rds, ecr, observability), dev environment,
                  and identity-eval (temporary Cognito evaluation root; not part of the dev stack)
evaluations/      Golden dataset, adversarial/security cases, offline tests, live M7.5/M7.6/M8.5 harnesses
policy/           Conftest/OPA Terraform policies and fixtures (CI gate)
policies/         Additional policy-as-code and IAM baselines
observability/    Collector, Prometheus, Grafana, dashboard and alarm definitions
tools/            Patched ADOT collector build
docs/             Architecture, governance, security evidence, runbooks, ADRs
scripts/          DB init, ingestion, evaluation runners, live Cognito validation and its Terraform wrapper
synthetic-data/   Synthetic document corpus (no real data)
```

## Roadmap

| Milestone | Goal | Status |
|---|---|---|
| M1 | Working cited RAG flow, packaging, lint/type/test baseline | Complete |
| M2 | Tenant-aware retrieval, classification, authorization and misuse-case tests | Complete (identity was a header resolver until M8) |
| M3 | Measurable AI behavior: golden dataset and offline evaluation gates in CI | Complete (deterministic gates); live Bedrock evaluation added in M7.5/M7.6 |
| M4 | Trustworthy release: IaC, secret, dependency and container scanning, policy-as-code, SBOMs, build evidence | Complete ([evidence](docs/security/MILESTONE_4_EVIDENCE.md)); container signing and signed provenance not delivered |
| M5 | AWS delivery: Terraform foundation, live private ECS/RDS deployment, verification, teardown | Complete (historical live deployment); runtime since costed down ([runbook](docs/runbooks/DEPLOYMENT_RUNBOOK.md)) |
| M6 | Observability: OpenTelemetry, ADOT, CloudWatch metrics/dashboard/alarms, local Prometheus/Grafana | Complete (observability scope; [evidence](docs/observability/M6_OBSERVABILITY_EVIDENCE.md)) |
| M7 | AI security: adversarial corpus, AUTHZ-01 fix, prompt-boundary and output/citation hardening, live baseline, Guardrails evaluation, evidence closure | Complete (AI-security scope; [evidence index](docs/security/M7_AI_SECURITY_EVIDENCE_INDEX.md)) |
| M8 | Production identity hardening: verified Cognito access tokens replace caller-supplied identity (ID-01) | Complete in code and real-PostgreSQL integration tests ([evidence](docs/security/M8_IDENTITY_EVIDENCE.md)); **live Cognito verification not executed; not deployed** |

Qualifiers: the S2 sensitive-output detector gap remains open; Guardrails were evaluated but not adopted; live model results are bounded observations, not guarantees; ID-01 is closed in code but its live verification and deployment prerequisites are open. Not delivered from the original plan: SQS/DLQ ingestion, a standalone cost report, demo recording, container image signing. Out of scope by decision: Backstage, Kubernetes variant, multi-cloud, SaaS control plane, always-on infrastructure.

## Deployment readiness

**Project complete ≠ production ready.** The platform is not approved for network-exposed production deployment until these are resolved ([M8 evidence](docs/security/M8_IDENTITY_EVIDENCE.md#deployment-prerequisites-open), [M7 deployment gate](docs/security/M7_AI_SECURITY_EVIDENCE_INDEX.md#deployment-gate)):

- **Live identity verification:** the M8 verifier has not been run against real Cognito tokens, and no approved production identity provider exists.
- **JWKS network access remains a deployment blocker:** ECS tasks run in private subnets without NAT and cannot reach Cognito's signing-key endpoint; a deployed service would fail closed (503) on every protected route. A supported network path must be designed and validated.
- **Pre-M8 image digests require replacement:** the preserved app and bootstrap images predate M8 (they trust caller identity headers) and must not be redeployed.
- **OIDC configuration:** `oidc_issuer` and `oidc_client_ids` must be set (they default to empty, which fails closed; Terraform only warns).
- **S2 sensitive-output gap:** the application detector misses one synthetic internal-key family (M7.5 LIVE-S2 reached the caller 3/3); the M7.6 output-regex experiment was promising but inconclusive.
- **Security exceptions:** temporary, dated Trivy CVE exceptions and deferred Checkov items; next mandatory review **2026-12-04** ([`.trivyignore.yaml`](.trivyignore.yaml), [deployment runbook](docs/runbooks/DEPLOYMENT_RUNBOOK.md)).
- **Operator identity:** Terraform and evaluations still run as a long-lived administrator IAM user in the AWS Organizations management account.
- **Cleanup:** an unused ALB security group is an open remediation item.
- **Future architecture:** ingress, rate limiting and the other items under [Future production architecture](#future-production-architecture).

## Known limitations

- All data is synthetic; governance mappings are alignment exercises, not certifications.
- Offline evaluations provide deterministic regression gates. M7.5 and M7.6 add bounded live Bedrock evaluations (3 repetitions per case); those results are empirical observations of nondeterministic model behavior, not universal guarantees.
- Identity verification is stateless: a revoked token or a removed group remains effective until the access token expires; keep access-token lifetimes short.
- Verified identity has been validated against real PostgreSQL RLS but not against live Cognito.
- The sensitive-output detector has a known coverage gap (S2); request input and `/v1/generate` output are not checked; there is no per-identity rate limiting.
- Row-level security is verified only against a real PostgreSQL instance (CI `integration-tests` job, or locally with `TEST_ADMIN_DATABASE_URL` and `TEST_DATABASE_URL` set); see [FINDINGS.md](docs/security/FINDINGS.md) F-001 for why the runtime role's privileges are asserted rather than assumed.
- pgvector is chosen for cost and reproducibility, not maximum-scale search.
- No AWS environment is kept running; the dev runtime is currently costed down.

## Governance and evidence

- [Threat model](docs/governance/THREAT_MODEL.md)
- [NIST AI RMF mapping](docs/governance/NIST_AI_RMF_MAPPING.md)
- [OWASP LLM Top 10 (2025) mapping](docs/governance/OWASP_LLM_TOP_10_MAPPING.md)
- [MITRE ATLAS mapping](docs/governance/MITRE_ATLAS_MAPPING.md)
- [M8 identity evidence](docs/security/M8_IDENTITY_EVIDENCE.md)
- [M7 AI-security evidence index](docs/security/M7_AI_SECURITY_EVIDENCE_INDEX.md)
- [AI incident response runbook](docs/runbooks/AI_INCIDENT_RESPONSE_RUNBOOK.md)
- [Architecture decision records](docs/adr/)
- [Security policy](SECURITY.md)

## License

MIT
