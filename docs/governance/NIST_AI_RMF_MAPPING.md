# NIST AI RMF Mapping (M7 final)

Maps platform evidence to the **NIST AI Risk Management Framework (AI RMF
1.0)** functions and to risks named in the **Generative AI Profile (NIST AI
600-1)**. This is an alignment exercise for a reference implementation - not
a certification, audit, or formal compliance claim. Mapping is at the
function level; no subcategory-level conformance is claimed. AI RMF 1.0 is
subject to ongoing revision; this mapping stays pinned to AI RMF 1.0 and
NIST AI 600-1 for the M7 closure.

AI 600-1 risks most relevant to this RAG system: **Information Security**
(prompt injection, data poisoning), **Data Privacy** (sensitive-information
leakage), **Confabulation** (ungrounded answers), **Information Integrity**,
**Human-AI Configuration** (over-reliance), **Value Chain and Component
Integration** (third-party model and images).

## GOVERN

| Theme | Evidence |
|---|---|
| Risk documentation | [Threat model](THREAT_MODEL.md) (reconciled at M7.7); [M7 evidence index and finding register](../security/M7_AI_SECURITY_EVIDENCE_INDEX.md) |
| Known limitations stated openly | README "Known limitations"; residual-risk register in the evidence index (ID-01, S2 detector gap, `LOG_FULL_CONTENT`, `/v1/generate` output, rate limiting) |
| Evidence-based technology decisions | [ADR 0005](../adr/0005-do-not-adopt-bedrock-guardrails.md): Bedrock Guardrails evaluated (M7.6) and not adopted |
| Accountability for open findings | ID-01 recorded as an OPEN finding and a deployment gate; S2 detector gap recorded as OPEN, not hidden by Guardrail results |
| Pre-registration and integrity of evaluations | M7.5/M7.6 cases, rules and configurations frozen before live calls, with SHA-256 pins; results not rerun or tuned after viewing |

## MAP

| Theme | Evidence |
|---|---|
| Context and trust boundaries | RAG boundaries in the threat model: caller -> API, system prompt vs caller question vs retrieved passages, service -> PostgreSQL (tenant boundary), service -> Bedrock |
| Tenant boundary | Tenant, classification and per-document ACL filters in SQL; PostgreSQL RLS; runtime role without RLS bypass (`app/tests/test_rls_integration.py`) |
| System / user / retrieved-content separation | M7.2 per-request unforgeable boundary framing (`app/rag/prompting.py`, `app/tests/test_prompting.py`) |
| Risk identification | M7.1 adversarial corpus: 22 cases tagged with OWASP LLM 2025 and MITRE ATLAS IDs ([ATLAS mapping](MITRE_ATLAS_MAPPING.md), [OWASP mapping](OWASP_LLM_TOP_10_MAPPING.md)) |
| Impact characterization | Synthetic data only; production impact assumptions stated in the threat model |

## MEASURE

| Theme | Evidence |
|---|---|
| Deterministic adversarial suite (M7.1) | 22 cases: 20 enforced, 1 characterization (ID-01C), 1 strict xfail (ID-01); run in CI (`evaluations/tests/test_adversarial_offline.py`) |
| Live no-Guardrails baseline (M7.5) | 54/54 calls: 33 `model_resisted`, 15 `model_correct`, 3 `application_blocked`, 3 `model_failed`, 0 runtime errors ([M7.5](../security/M7_5_LIVE_ADVERSARIAL_BASELINE.md)) |
| Guardrails comparison (M7.6) | M7.6a 54/54 (0 unsafe final outcomes; 47 interventions; unacceptable false refusals/positives); M7.6b-A S2 exposure 0/3, verdict INCONCLUSIVE; M7.6b-B MEDIUM identical to HIGH ([M7.6](../security/M7_6_GUARDRAILS_COMPARISON.md)) |
| False-refusal / usability measurement | M7.6a: 5/6 answerable/conflict runs refused; harmless G4 blocked 3/3 at HIGH and MEDIUM |
| Sensitive-output exposure | M7.5 LIVE-S2 3/3 reached caller (detector coverage gap); LIVE-S1 3/3 withheld by the application |
| Separation of measured actors | Model resistance, guardrail intervention and application blocking are scored separately; guardrail blocks are never counted as model resistance |
| Limits of measurement | 3 repetitions per case; nondeterministic model; synthetic fixtures; observations, not guarantees |

## MANAGE

| Theme | Evidence |
|---|---|
| Remediated findings | AUTHZ-01 (unauthorized document replacement) fixed with real-PostgreSQL, race and ACL regressions; IPI structural findings fixed (M7.2); citation integrity enforced (M7.3) |
| Output controls | Citation validation, fail-closed unsupported answers, withhold/redact sensitive output on `/v1/query` (`app/rag/output_integrity.py`) |
| Technology non-adoption decision | Guardrails not adopted ([ADR 0005](../adr/0005-do-not-adopt-bedrock-guardrails.md)); application controls remain primary |
| Residual-risk register and deployment gate | Evidence index: no public/network-exposed production deployment while ID-01 is open |
| Incident response | [AI incident response runbook](../runbooks/AI_INCIDENT_RESPONSE_RUNBOOK.md) |
| Cost and exposure management | Dev runtime intentionally costed down; see [deployment runbook](../runbooks/DEPLOYMENT_RUNBOOK.md) |
