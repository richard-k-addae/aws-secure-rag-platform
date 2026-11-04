# M7 AI-Security Evidence Index (M7.7 closure)

**M7 status: COMPLETE - AI-security evaluation and hardening scope.** This
is project completion for the M7 scope, **not** production deployment
readiness and not a certification. ID-01 remains open and is a deployment
prerequisite (see "Deployment gate").

Closed 2026-11-04 on branch `m6/observability` (M7 commits `773b6ba`
M7.1, `59dbb36` M7.4a, `9f6aee7` M7.2, `e4306f2` M7.3, `d16af07`/`158a3cd`
M7.5, `962b6ab` M7.6). Every row cites evidence that exists in the
repository; nothing is inferred.

Status values: **CONFIRMED COMPLETE**, **OPEN FINDING**, **DEFERRED**,
**EVALUATED / NOT ADOPTED**, **OUT OF SCOPE**. Evidence type:
**Deterministic** (structural tests, same result every run) or **Live /
model-dependent** (bounded Bedrock runs; observations, not guarantees).

## Evidence index

| Milestone | Control / finding | Status | Evidence file | Test / evaluation | Type | Limitations | Final disposition |
|---|---|---|---|---|---|---|---|
| M7.1 | Unified adversarial corpus (22 cases, OWASP LLM 2025 + ATLAS tags) | CONFIRMED COMPLETE | `evaluations/security/adversarial_cases.json`, `evaluations/security/README.md` | `evaluations/tests/test_adversarial_offline.py` (20 enforced, 1 characterization, 1 strict xfail) | Deterministic | Structural checks; no claim about model behaviour. ATLAS tags are the identifiers used when the corpus was created and are kept unchanged; current-taxonomy crosswalks for `AML.T0056`/`AML.T0057` are in the [ATLAS mapping](../governance/MITRE_ATLAS_MAPPING.md) | Retained as CI regression suite |
| M7.1 | Prompt-injection fixtures through the real RAG structure | CONFIRMED COMPLETE | `evaluations/security/prompt_injection_cases.json` | `evaluations/tests/test_prompt_injection.py` | Deterministic | Structural confinement only | Retained |
| M7.1 / M7.4a | Real-PostgreSQL authorization and RLS tests | CONFIRMED COMPLETE | `app/tests/test_rls_integration.py` | 25 tests; run in CI `integration-tests` job; **executed for this closure locally against `pgvector/pgvector:pg16` replicating that job: 25 passed** (2026-11-04) | Deterministic | Skipped without `TEST_*_DATABASE_URL`; the M7 branch has no CI runs yet (see R8) | Retained |
| M7.4a | AUTHZ-01 unauthorized document replacement | CONFIRMED COMPLETE | `app/rag/retrieval.py`, `app/rag/ingestion.py`, `app/api/routes/documents.py` | `test_ingestor_cannot_overwrite_restricted_document_by_id`, `test_rejected_overwrite_is_atomic_leaks_nothing_and_emits_one_event`, `test_store_refuses_unauthorized_replacement_directly`, `test_concurrent_restricted_writer_is_serialized_before_authorization`, `test_document_acl_excluding_caller_blocks_replacement` (real PostgreSQL); `test_authorize_as_is_required_and_keyword_only_on_every_write_path`, `test_omitting_authorize_as_fails_before_any_write` (`app/tests/test_tenant_isolation.py`); corpus AUTHZ-01 enforced | Deterministic | Writer identity depends on ID-01; trusted operator path (`authorize_as=None`) not separately authenticated | Fixed |
| M7.2 | Structural prompt boundaries (indirect-injection findings IPI-02..06) | CONFIRMED COMPLETE | `app/rag/prompting.py`, `app/tests/prompt_frame.py` | `app/tests/test_prompting.py` (boundary freshness, collision regeneration, fail-closed, weak-token rejection, hostile source encoding); IPI-02..06 enforced | Deterministic | Structure cannot be forged; model may still be persuaded by content | Fixed |
| M7.2 | Unicode / hidden-control normalization | CONFIRMED COMPLETE | `app/core/security.py` | `app/tests/test_security.py` (`test_sanitize_strips_control_characters`, `test_sanitize_preserves_legitimate_joiners_and_marks`) | Deterministic | Normalization, not semantic screening | Retained |
| M7.2 | Prompt budget and question-size contract | CONFIRMED COMPLETE | `app/rag/prompting.py`, `app/core/config.py`, `app/models/requests.py` | `app/tests/test_prompt_budget.py` | Deterministic | Size limits are not rate limits (R7) | Retained |
| M7.3 | Citation integrity (OUT-01) | CONFIRMED COMPLETE | `app/rag/output_integrity.py`, `app/models/responses.py` | `app/tests/test_output_integrity.py` (canonical in-range indices only, cited-only and de-duplicated citations, retrieved text never parsed, invalid/uncited answers fail closed); OUT-01 enforced | Deterministic | Valid citation is not proof of faithfulness | Fixed |
| M7.3 | Sensitive-output withholding/redaction on `/v1/query` (OUT-02) | CONFIRMED COMPLETE (scope-limited) | `app/rag/output_integrity.py`, `app/core/sensitive_data.py` | `app/tests/test_output_integrity.py` (secret withheld even when validly cited, email masked, withheld answers never logged); OUT-02 enforced; `evaluations/tests/test_sensitive_data.py` | Deterministic | Pattern-based; misses the S2 key family (R2); `/v1/generate` output and request input unchecked (R5) | Retained as primary output control |
| M7.5 | Live no-Guardrails baseline | CONFIRMED COMPLETE | `evaluations/security/m7_5_live_cases.json`, `evaluations/security/m7_5_live_baseline.json`, [M7.5 report](M7_5_LIVE_ADVERSARIAL_BASELINE.md) | `scripts/run_live_adversarial_baseline.py`, `evaluations/live/m7_5_baseline.py`; offline rules `evaluations/tests/test_live_baseline_rules.py` | Live / model-dependent | 3 repetitions per case; synthetic fixtures; ID-01 excluded | Baseline of record |
| M7.5 | Sensitive-output detector gap (LIVE-S2) | OPEN FINDING | `m7_5_live_baseline.json` (LIVE-S2 3/3 `model_failed`) | M7.5 live run | Live / model-dependent | Synthetic key; application detector does not cover this key family | Open (R2) |
| M7.6 | Bedrock Guardrails comparison (M7.6a, M7.6b-A, M7.6b-B) | CONFIRMED COMPLETE (evaluation) | `evaluations/security/m7_6_guardrail_definition.json`, `m7_6b_a_guardrail_definition.json`, `m7_6b_b_guardrail_definition.json`, `m7_6_guardrails_baseline.json`, `m7_6b_guardrails_tuning.json`, [M7.6 report](M7_6_GUARDRAILS_COMPARISON.md) | `evaluations/live/m7_6_guardrails.py`, `evaluations/live/m7_6b_tuning.py`; offline `test_live_guardrails_rules.py`, `test_live_guardrails_tuning.py` (pre-registration hashes; M7.5/M7.6a artifacts pinned with LF-normalized SHA-256) | Live / model-dependent | Small samples; one guardrail design; Standard grounding not testable with pinned tooling | Evaluation of record |
| M7.6 | Prompt-attack Guardrail HIGH | EVALUATED / NOT ADOPTED | M7.6a | 39/54 input blocks; harmless G4 blocked 3/3 | Live / model-dependent | - | Not adopted ([ADR 0005](../adr/0005-do-not-adopt-bedrock-guardrails.md)) |
| M7.6 | Prompt-attack Guardrail MEDIUM | EVALUATED / NOT ADOPTED | M7.6b-B | Identical to HIGH on all 14 tested cases; G4 blocked 3/3 | Live / model-dependent | - | Not adopted |
| M7.6 | Classic contextual grounding | EVALUATED / NOT ADOPTED | M7.6a | 5/6 answerable/conflict runs refused | Live / model-dependent | - | Rejected for this use case |
| M7.6 | Output sensitive-information regex (S2 family) | EVALUATED / NOT ADOPTED | M7.6b-A | S2 exposure 0/3; anonymized 2/2 observed emissions; verdict INCONCLUSIVE | Live / model-dependent | Exercised twice; written for a known key family | Not adopted; candidate for a future pre-registered run |
| M7.6 | Standard contextual grounding | DEFERRED | - | Not run | - | Not exposed by AWS CLI 2.34.30 / botocore 1.43.63 | Deferred until pinned tooling supports it |
| M7 | ID-01 caller-controlled identity | OPEN FINDING | `app/auth/tenancy.py` | Corpus ID-01 strict xfail; ID-01C characterization | Deterministic | - | Open; deployment gate (R1) |
| M7 | Model training / fine-tuning attacks | OUT OF SCOPE | [Threat model](../governance/THREAT_MODEL.md) | - | - | No training occurs | Out of scope |

The evaluation guardrail used in M7.6 (`4og2m4vup8gv`) was deleted on
2026-11-04 after the evidence was committed; it was not referenced by any
application configuration, IAM policy, Terraform state or deployment.

## M7 finding register

| Finding | Status | Evidence | Notes |
|---|---|---|---|
| AUTHZ-01 unauthorized document replacement | **CONFIRMED COMPLETE** | Real PostgreSQL (25/25 RLS/authorization tests), race/atomicity (`test_concurrent_restricted_writer_is_serialized_before_authorization`, `test_rejected_overwrite_is_atomic_...`), per-document ACL checks, fail-closed keyword-only `authorize_as` contract | Fixed in M7.4a |
| IPI structural injection findings (IPI-02..06) | **CONFIRMED COMPLETE** | M7.2 boundary framing; corpus enforced; `app/tests/test_prompting.py` | Structural; model behaviour measured separately (M7.5 indirect 12/12 resisted) |
| Citation integrity (OUT-01) | **CONFIRMED COMPLETE** | M7.3; `app/tests/test_output_integrity.py` | `/v1/query` |
| Sensitive-output detector gap (S2) | **OPEN FINDING** | M7.5 LIVE-S2 reached the caller 3/3 without Guardrails | M7.6 output regex promising but INCONCLUSIVE under the pre-registered rule; not adopted |
| ID-01 caller-controlled identity | **OPEN FINDING** | Tenant/role still derive from `X-Tenant-Id` / `X-Tenant-Role` headers | Deployment blocker |
| Classic contextual grounding | **EVALUATED / NOT ADOPTED** | M7.6a | Unacceptable refusals |
| Prompt-attack Guardrail HIGH | **EVALUATED / NOT ADOPTED** | M7.6a | Over-blocking, false positive on G4 |
| Prompt-attack Guardrail MEDIUM | **EVALUATED / NOT ADOPTED** | M7.6b-B | No usability improvement |
| Standard contextual grounding | **DEFERRED** | - | Pending support in pinned tooling |

Pre-M7 findings remain in [FINDINGS.md](FINDINGS.md) (F-001).

## M7 security scorecard

Reported per evaluation; deliberately not collapsed into a single security
percentage.

| Evaluation | Result |
|---|---|
| Deterministic adversarial corpus (M7.1, CI) | 22 cases: 20 enforced, 1 characterization (ID-01C), 1 strict xfail (**ID-01**, the only remaining) |
| M7.5 live baseline, no Guardrails | 54/54 calls: 33 `model_resisted`, 15 `model_correct`, 3 `application_blocked` (S1), 3 `model_failed` (S2), 0 runtime errors |
| M7.6a Guardrails v1 | 54/54 calls; 47 guardrail interventions; 0 unsafe final outcomes; unacceptable false refusals (5/6 answerable/conflict runs) and false positives (G4 3/3) |
| M7.6b-A S2 output-regex isolation | S2 final exposure 0/3; regex intervened on 2/2 observed emissions; verdict **INCONCLUSIVE** |
| M7.6b-B prompt attack MEDIUM | Same behaviour as HIGH on all tested cases; G4 false positive 3/3; usability target **not met**; 0 unsafe final outputs |

## Guardrail decision

No tested Bedrock Guardrail configuration is adopted
([ADR 0005](../adr/0005-do-not-adopt-bedrock-guardrails.md)): HIGH
prompt-attack filtering over-blocked; MEDIUM did not improve usability;
Classic grounding caused unacceptable refusals; the S2 output regex is
promising but inconclusive; Standard grounding is deferred. Application
controls remain primary. This is a deliberate, evidence-based non-adoption
decision, not an unfinished implementation.

## Residual risks

| # | Risk | Detail | Disposition |
|---|---|---|---|
| R1 | **ID-01** caller-controlled tenant/role | Identity from validated request headers, not verified credentials | Open; **deployment blocker** for any network exposure |
| R2 | **S2 detector coverage** | Application detector does not recognize one synthetic internal-key family; M7.6 regex showed potential but is not adopted or proven | Open |
| R3 | `LOG_FULL_CONTENT` | Development-only raw prompt/response logging (`app_env == "dev"`) remains a disclosure surface | Accepted for dev; must stay off elsewhere |
| R4 | Standard contextual grounding | Not evaluated: not exposed by pinned AWS tooling | Deferred |
| R5 | Unchecked output/input paths | `/v1/generate` (admin-only) output and request input are not checked by the sensitive-data detector | Open |
| R6 | No ingestion-time content scanning | Authorized writers can store malicious or poisoned text | Open (structural confinement only) |
| R7 | No per-identity rate limiting / quotas | Size and token limits exist; throttling relies on Bedrock 503 handling | Open |
| R8 | CI verification of this branch | `ci.yml`/`security.yml` run on `pull_request` and pushes to `main`; `m6/observability` has no workflow runs. The latest scheduled `Security` run on `main` (2026-11-02) failed: pip-audit (`urllib3` 2.7.0 on `main`; this branch pins 2.8.0), gitleaks (5 hits on synthetic test constants), TruffleHog (scheduled run with base == head) and Trivy | Open: open a PR to run CI on this branch and triage these jobs |
| R9 | Review deadlines on 2026-11-09 | All `.trivyignore.yaml` entries expire and all Checkov skips (including the temporary `CKV_AWS_293`) carry "Review by 2026-11-09" | Open: review before that date |
| R10 | Operator identity | Terraform and evaluations run as a long-lived IAM user with AdministratorAccess; CI OIDC not implemented | Open |
| R11 | Container image signing | Not implemented as a pipeline control (known gap in M4/M6.4 evidence) | Open |
| R12 | ATLAS taxonomy maintenance | Corpus ATLAS tags (including `AML.T0056`/`AML.T0057`) are historical identifiers kept for evidence integrity; related current techniques are recorded as crosswalks | Documented; re-review tags against the current taxonomy as governance maintenance |
| R13 | Model-dependent evidence | M7.5/M7.6 are bounded observations (3 repetitions, synthetic data), not universal guarantees | Inherent; re-measure on model change |

## Deployment gate

**The platform must NOT be treated as ready for public or network-exposed
production deployment while ID-01 remains unresolved.** Additional
prerequisites before any such deployment: R8 (green CI on the merged code),
R2 or an accepted alternative for sensitive output, R7 and R9.

**Project completion is distinct from production deployment readiness.**
The M7 research/portfolio scope - adversarial corpus, authorization fix,
prompt and output hardening, live baseline and Guardrails evaluation - is
complete with its evidence, findings and residual risks recorded here. That
does not make the system production-ready.

## Verification performed at M7.7

- Repository gates (`run_evaluations.py`, pytest, ruff, mypy, `git diff --check`) - see the M7.7 commit.
- Real-PostgreSQL suite executed locally against `pgvector/pgvector:pg16`, reproducing the CI `integration-tests` job: 25 passed.
- Final ATLAS mapping reconciled against the current ATLAS taxonomy; historical corpus tags unchanged, with crosswalks recorded.
- Evaluation guardrail deleted after verifying it had no references.
- Committed live evidence contains bounded results only: no raw model output, Guardrail trace match values, canary values, offer tokens or credentials.
