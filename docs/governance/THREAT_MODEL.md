# Threat Model — AWS Secure RAG Platform

Methodology: STRIDE applied to each trust boundary, extended with
AI-specific threats from the OWASP Top 10 for LLM Applications 2025 and
MITRE ATLAS ([ATLAS mapping](MITRE_ATLAS_MAPPING.md),
[OWASP mapping](OWASP_LLM_TOP_10_MAPPING.md)). Synthetic data only; severity
ratings assume a production deployment of the same architecture.

Reconciled with the implementation at M7.7 (2026-11-04) and updated for M8
verified identity (2026-11-05). Mitigations below describe what is
implemented and tested today; target-architecture items that are not
implemented are marked as such. M8 identity controls are enforced in code and
tested against real PostgreSQL; **real Cognito verification has not been
executed** and no deployment runs the M8 code
([M8 evidence](../security/M8_IDENTITY_EVIDENCE.md)).

## System assets

- Foundation model access (Bedrock invocation rights)
- Knowledge base content and embeddings (PostgreSQL + pgvector), per tenant
- Tenant and role identity (M8: derived from verified Cognito access-token groups)
- Identity-provider trust anchors: configured issuer, app client allowlist, tenant allowlist, JWKS signing keys
- System prompt and request framing
- Audit logs and telemetry
- CI/CD pipeline and container images

## Trust boundaries

1. Caller -> FastAPI service. **Current (M8):** the caller presents a Cognito
   access token (`Authorization: Bearer`); the service verifies it (RS256,
   issuer, expiry, `token_use`, `client_id`) and derives tenant and role only
   from `cognito:groups`. Caller headers, query string and body carry no
   identity authority. **Not implemented:** API Gateway/WAF, TLS ingress.
1a. Service -> identity provider JWKS endpoint (key retrieval). Trusted URI
   derived from configuration only; no redirects; cached with bounded
   refresh. **Deployment gap:** no network path from ECS tasks (R14).
2. Inside the prompt: system prompt (trusted) vs caller question
   (untrusted) vs retrieved passages (untrusted data). Separated by M7.2
   per-request unforgeable boundary framing.
3. Service -> PostgreSQL/pgvector: tenant boundary enforced by SQL filters
   and PostgreSQL row-level security under a runtime role that cannot bypass
   RLS.
4. Service -> Bedrock (IAM, VPC endpoint when deployed).
5. Writers -> knowledge base: ingestion and replacement authorized against
   the caller's scope and the existing document's policy (AUTHZ-01).
6. Operator workstation -> AWS (Terraform and evaluation runs use a local
   IAM user). **Target (not implemented):** GitHub Actions -> AWS via OIDC;
   CI currently has no AWS access.

## Key threats and mitigations

| # | Threat | Vector | Implemented mitigations | Status / residual |
|---|--------|--------|-------------------------|-------------------|
| T1 | Direct prompt injection | Caller question | Per-request unforgeable boundary framing; system prompt treats the question as data; input size limit; hidden-control-character normalization; deterministic suite DPI-001..011; live baseline M7.5 | Mitigated structurally; model resistance **measured, not guaranteed** (M7.5 12/12 direct). No input classifier: Bedrock prompt-attack filter evaluated in M7.6 and **not adopted** |
| T2 | Indirect prompt injection | Malicious text in retrieved documents | Retrieved content is untrusted data inside boundary tags it cannot forge; forged passage/question/role markers stay data; citations validated against passages actually provided; IPI-02..06 | Mitigated structurally; model resistance measured (M7.5 12/12 indirect). **No ingestion-time content scanning** |
| T3 | Sensitive data disclosure | Model output repeats sensitive values or system instructions | M7.3 sensitive-output check on `/v1/query` (withhold credentials/identifiers, mask emails) before citation processing; metadata-only logging by default; system prompt holds no secrets | **Open:** S2 detector coverage gap (M7.5 S2 3/3 reached caller); `/v1/generate` output and request input unchecked; `LOG_FULL_CONTENT` dev mode can log raw responses |
| T4 | Unauthorized document access (read) | Caller queries beyond tenant/role | Tenant, classification and per-document ACL filters in the retrieval SQL; PostgreSQL RLS (FORCEd, fail-closed when tenant unset); runtime role `NOSUPERUSER NOBYPASSRLS` | Implemented and tested against real PostgreSQL, including with verified tokens (M8.4); live Cognito not verified |
| T5 | Unauthorized document replacement / RAG poisoning | Writer overwrites an existing document | AUTHZ-01: authorize against the existing document's classification and ACL, atomically, with serialized concurrent writers; keyword-only `authorize_as` with no default | Implemented (M7.4a). Authorized writers can still ingest malicious content |
| T6 | Model cost abuse / token exhaustion | Oversized or repeated requests | Question limit 4,000 chars; prompt budget 8,000 chars; `max_output_tokens` 1,024; controlled 503 on throttling; no model call without context | Partial: **no per-identity rate limiting** (target API Gateway throttling not implemented) |
| T7 | Credential theft | Long-lived keys in CI or code | No AWS credentials in CI; TruffleHog and Gitleaks gates; Secrets Manager for database credentials at runtime | Partial: local operator access uses a long-lived, broadly privileged IAM user (CI OIDC is a target, not implemented) |
| T8 | Supply-chain compromise | Malicious dependency or image | Hash-locked dependencies, pip-audit, Trivy, SBOMs, digest-pinned images, Conftest/Checkov | Image signing not implemented as a pipeline control (known gap) |
| T9 | Hallucinated / ungrounded answers | Model asserts unsupported claims | Deterministic no-context refusal without model call; invalid or uncited answers replaced by a fixed message; groundedness eval gates | Citation validity is not factual-faithfulness proof. Classic contextual grounding **rejected** (M7.6); Standard grounding deferred |
| T10 | Audit log tampering | Attacker hides activity | CloudTrail; KMS-encrypted log groups when deployed | Dev runtime currently costed down |
| T11 | Caller identity spoofing (ID-01) | Caller sets tenant/role headers or forges a token | M8: identity headers removed; verified RS256 access token; issuer and app client allowlist; tenant allowlist; exactly one tenant and one role group, else 403 | **Enforced in code and real-PostgreSQL tests.** Real Cognito verification not executed; deployment prerequisites R1, R14, R16 |
| T12 | Token replay, revocation and group-change lag | Stolen or revoked token reused before expiry; removed group still in a live token | Short access-token lifetime; `token_use`/`client_id` binding; no token logging | **Open (R15):** verification is stateless; revocation is not observed before expiry |
| T13 | Identity-provider key endpoint unavailable or unusable | Outage, network block, malformed key set | Fail closed with 503; failure backoff; last good key set retained; unusable responses rejected | Implemented and tested; **no deployed network path (R14)** |
| T14 | Algorithm / key-source manipulation | `alg=none`, HS256 confusion, `jku`/`x5u`/`jwk` headers, unknown `kid` floods | Fixed RS256; key source only from configured issuer; header URLs ignored; bounded `kid` and token size; one refresh per cooldown | Implemented and tested (M8.1, M8.4) |

Bedrock Guardrails are **not** enabled. They were evaluated in M7.6 and
deliberately not adopted ([ADR 0005](../adr/0005-do-not-adopt-bedrock-guardrails.md)).
No control here is claimed to prevent prompt injection universally.

## Out of scope

Model training attacks (no training or fine-tuning occurs); DDoS
protection (no API Gateway/WAF in the current implementation);
embedding-inversion attacks.

Review cadence: revisit at each phase completion and whenever the identity
provider or its deployment path, the sensitive-output detector or Guardrail
adoption changes.
