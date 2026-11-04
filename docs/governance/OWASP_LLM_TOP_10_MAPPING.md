# OWASP Top 10 for LLM Applications 2025 - Control Mapping (M7 final)

Alignment exercise against the **OWASP Top 10 for LLM Applications 2025**,
the **pinned taxonomy** used for the M7 evaluation (corpus tags
`LLMxx:2025`). It is not an OWASP compliance claim, certification or
assessment.

**Edition note.** This mapping is not presented as the latest OWASP edition
as of project closure: OWASP released a 2026 edition after the project's
taxonomy was pinned. M7 was evaluated and is closed against the 2025
edition; remapping to the 2026 edition is a future governance-maintenance
item, not a prerequisite for closing M7.7.

Status values:
**Implemented** (control with deterministic tests), **Partial**, **Open**,
**Not applicable**.

| ID | Risk | Applicable | Implemented controls | Test / evidence | Residual risk | Status |
|---|---|---|---|---|---|---|
| LLM01:2025 | Prompt Injection | Yes | M7.2 per-request unforgeable boundary framing of passages and question; hidden-control-character normalization; system prompt states retrieved text is data; M7.3 citation validation and output checks | DPI-001..011, IPI-02..06 enforced (`evaluations/tests/test_adversarial_offline.py`, `test_prompt_injection.py`); `app/tests/test_prompting.py`; M7.5 direct 12/12 and indirect 12/12 `model_resisted` | Model resistance is observed, not guaranteed; no input classifier adopted (Bedrock prompt-attack filter evaluated in M7.6, not adopted: over-blocking) | Partial (structural controls implemented; model behaviour measured) |
| LLM02:2025 | Sensitive Information Disclosure | Yes | Tenant, classification and per-document ACL filtering in SQL plus PostgreSQL RLS; M7.3 sensitive-output check on `/v1/query` answers (withhold credentials/identifiers, mask emails); metadata-only logging by default | `app/tests/test_tenant_isolation.py`, `app/tests/test_rls_integration.py`, `app/tests/test_output_integrity.py`, OUT-02; M7.5 S1 3/3 `application_blocked` | **S2 detector coverage gap** (M7.5 S2 3/3 reached caller); `/v1/generate` output and request input not checked; ID-01 means identity is caller-asserted; `LOG_FULL_CONTENT` dev mode | Open (S2 gap, ID-01) |
| LLM03:2025 | Supply Chain | Yes | Pinned and hash-locked dependencies (`uv.lock`, `pip-audit --require-hashes`); Trivy, Checkov, TruffleHog, Gitleaks, Conftest gates; CycloneDX SBOMs; digest-pinned images; patched ADOT image built in-project | `.github/workflows/security.yml`; [Milestone 4 evidence](../security/MILESTONE_4_EVIDENCE.md); [M6.4 ADOT evidence](../security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md) | Container image signing is not implemented as a pipeline control (known gap recorded in M4/M6.4 evidence); managed foundation model is a third-party dependency outside project control | Implemented (M4/M6; not re-evaluated in M7) |
| LLM04:2025 | Data and Model Poisoning | Yes (retrieval corpus; no training) | AUTHZ-01: replacements authorized against the existing document policy, atomic, serialized; RLS `WITH CHECK`; writes scoped to the caller's read classification | AUTHZ-01 (enforced); `test_ingestor_cannot_overwrite_restricted_document_by_id`, `test_rejected_overwrite_is_atomic_leaks_nothing_and_emits_one_event`, `test_concurrent_restricted_writer_is_serialized_before_authorization` (real PostgreSQL) | Authorized writers can still ingest malicious content; no ingestion-time content scanning; writer identity depends on ID-01 | Partial |
| LLM05:2025 | Improper Output Handling | Yes | Citation indices validated against passages actually provided; invalid or uncited answers fail closed to a fixed message; only cited passages returned; model output never executed or rendered as code | OUT-01 (enforced); `app/tests/test_output_integrity.py` | `/v1/generate` (admin-only) output is not checked | Implemented for `/v1/query` |
| LLM06:2025 | Excessive Agency | Yes (by design) | Model has no tools, no write access, no autonomous actions; generation only | AG-01 (enforced) | Re-assess if tools or agents are added | Implemented (by design) |
| LLM07:2025 | System Prompt Leakage | Yes | System prompt holds no secrets or credentials; prompt framing; output checks | DPI-001, DPI-004, DPI-005, DPI-010 (enforced); M7.5 leakage 9/9 `model_resisted` | Leakage resistance is model behaviour; Standard-tier prompt-leakage detection evaluated in M7.6 (L1 not detected; not adopted) | Partial (measured) |
| LLM08:2025 | Vector and Embedding Weaknesses | Yes | Retrieval filtered by tenant, classification and per-document ACL inside the vector query; PostgreSQL RLS as an independent layer; runtime role cannot bypass RLS | `app/tests/test_tenant_isolation.py`, `app/tests/test_rls_integration.py` (incl. `test_runtime_role_cannot_bypass_row_security`); IPI-05; AUTHZ-01 | Identity feeding those filters is caller-asserted (ID-01); no embedding-inversion analysis | Partial (ID-01) |
| LLM09:2025 | Misinformation | Yes | Deterministic refusal with no model call when no context; answers must cite provided passages or are replaced; groundedness/refusal eval gates | `evaluations/tests/test_groundedness.py`, `test_response_quality.py`, OUT-01; M7.5 grounding 15/15 `model_correct` | Citation validity does not prove factual faithfulness; Classic contextual grounding rejected (M7.6: 5/6 legitimate answers refused); Standard grounding deferred | Partial |
| LLM10:2025 | Unbounded Consumption | Yes | Question limit 4,000 chars; prompt budget 8,000 chars; `max_output_tokens` 1,024; controlled 503 on Bedrock throttling; no model call without context | `app/tests/test_bedrock.py`, `app/tests/test_query.py`, `app/tests/test_prompt_budget.py`, `app/tests/test_failure_modes.py` | No per-identity rate limiting or quotas; M6 cost/usage alarms are not running while the dev runtime is costed down | Partial |

Evidence details: [M7 AI-security evidence index](../security/M7_AI_SECURITY_EVIDENCE_INDEX.md).
ATLAS techniques: [MITRE ATLAS mapping](MITRE_ATLAS_MAPPING.md).
