# Architecture Overview

## Request flow (target, Phase 4)

> **Implementation status (M8, 2026-11-05):** the service verifies Cognito
> user pool **access tokens** itself (RS256, issuer, expiry, `token_use`,
> `client_id`) and derives tenant and role only from `cognito:groups`
> ([M8 evidence](../security/M8_IDENTITY_EVIDENCE.md)); this is tested locally
> and against real PostgreSQL, **not yet against live Cognito**, and no
> production user pool exists. API Gateway/WAF (and its JWT authorizer),
> DynamoDB request records and Bedrock Guardrails are **not** implemented;
> Guardrails were evaluated and not adopted (ADR 0005). Implemented AI
> controls are application-layer: prompt boundaries, citation validation and
> sensitive-output withholding. See the
> [M7 evidence index](../security/M7_AI_SECURITY_EVIDENCE_INDEX.md).

1. Client authenticates against Cognito, receives JWT.
2. Request hits API Gateway: WAF rules, throttling, JWT authorizer.
3. FastAPI service on ECS Fargate (private subnet, no public IP) verifies the access token and derives tenant and role from its groups (implemented in M8; the deployed network has no JWKS path yet, R14).
4. Retrieval: query embedded, pgvector searched with metadata filters INCLUDING document-level authorization for the caller's role.
5. Retrieved chunks + user query -> Bedrock (via VPC endpoint), framed with per-request unforgeable boundaries; answer checked for valid citations and sensitive output before return.
6. Response returned with source citations; metadata (tokens, latency, model ID, withheld-answer reasons) logged redacted; request record written to DynamoDB.

## Ingestion flow (target, Phase 3)

S3 upload (synthetic docs) -> EventBridge -> SQS -> ingestion worker:
extract, chunk, embed, store in pgvector with metadata (source, roles,
timestamps). Failures -> DLQ with status tracking.

## Key decisions

### ADR-001: pgvector over OpenSearch Serverless for v1

RDS PostgreSQL + pgvector demonstrates the same RAG fundamentals
(vector similarity search, metadata filtering, private connectivity,
encryption, backups) without OpenSearch Serverless's always-on OCU cost
floor. OpenSearch Serverless becomes preferable at enterprise scale:
high ingest throughput, hybrid lexical+vector retrieval, native Bedrock
Knowledge Base integration. The service's retrieval layer is
interface-based so the store can be swapped.

### ADR-002: ECS Fargate over EKS for v1

Fargate keeps operational surface small and cost low while proving the
containerized-platform patterns. An EKS deployment variant (Helm,
ArgoCD) is a planned Phase 8 extension, reusing patterns from the
maintainer's existing aws-eks-gitops-platform project.

### ADR-003: Model ID as configuration

The Bedrock model ID is injected via environment/Parameter Store, never
hardcoded. The service targets the Converse API for cross-model
portability.
