# MITRE ATLAS Mapping (M7 final)

Alignment exercise, not a certification or assessment. Maps the ATLAS
techniques used in the M7 AI-security work to this platform's exposure,
controls and evidence.

**ATLAS version.** The M7.1 corpus
(`evaluations/security/adversarial_cases.json`) was tagged with the ATLAS
identifiers available when it was created. This final M7.7 mapping was
reconciled on 2026-11-04 against the current ATLAS taxonomy (technique IDs
and names cross-checked against the `mitre-atlas/atlas-data` repository).
No frozen ATLAS release artifact is committed to this repository, so this
document makes no claim about when any technique was added, renamed or
retired.

**Historical tags and crosswalk.** M7.1 used `AML.T0056` and `AML.T0057`.
Those corpus IDs remain unchanged for evidence integrity. Where a related
current technique improves the mapping, it is recorded here as a crosswalk
rather than by rewriting the historical evidence:

| M7.1 corpus tag (historical) | Name | Used for | Related current technique(s) used in this mapping |
|---|---|---|---|
| `AML.T0056` | Extract LLM System Prompt | DPI-001, DPI-005 | `AML.T0069.002` Discover LLM System Information: System Prompt |
| `AML.T0057` | LLM Data Leakage | DPI-003, DPI-010, OUT-02 | `AML.T0024` Exfiltration via AI Inference API; `AML.T0136` Exfiltration via AI User Interface |

Status values: **Mitigated (deterministic)** - enforced by a structural
control with a deterministic test; **Measured (model-dependent)** - observed
in bounded live runs, not guaranteed; **Open**; **Partial**; **Not
applicable**.

| Technique | Project exposure | Control | Test / evidence | Final status | Residual limitation |
|---|---|---|---|---|---|
| `AML.T0051.000` LLM Prompt Injection: Direct | Caller question on `/v1/query` | M7.2 per-request unforgeable boundary framing; system prompt states passages/question are data; M7.3 citation and output checks | DPI-001..DPI-011 (enforced, `test_adversarial_offline.py`, `test_prompt_injection.py`); M7.5 LIVE-D1..D4 12/12 `model_resisted` | Mitigated (deterministic) structurally; Measured (model-dependent) | Model resistance is observed on 4 cases x 3 runs, not guaranteed; no input classifier adopted (M7.6 prompt-attack filter evaluated, not adopted) |
| `AML.T0051.001` LLM Prompt Injection: Indirect | Retrieved passages are untrusted content inside the prompt | Passages framed as data with boundary tags the passage text cannot forge; source names JSON-encoded; hidden control characters normalized | IPI-02..IPI-06 (enforced); M7.5 LIVE-I1..I4 12/12 `model_resisted` | Mitigated (deterministic) structurally; Measured (model-dependent) | No ingestion-time content scanning; an authorized ingestor can still store malicious text |
| `AML.T0054` LLM Jailbreak | Persona / override attempts in the question | As for direct injection | DPI-002 (enforced); M7.5 LIVE-D2 3/3 `model_resisted` | Measured (model-dependent) | Small sample; model-dependent |
| `AML.T0069.002` Discover LLM System Information: System Prompt | System prompt sent with every request | System prompt contains no secrets; prompt framing; output checks | DPI-001, DPI-004, DPI-005, DPI-010 (enforced); M7.5 LIVE-L1..L3 9/9 `model_resisted` (system canary absent) | Measured (model-dependent) | Leakage resistance is model behaviour; M7.6 prompt-attack filter did not detect L1 |
| `AML.T0024` Exfiltration via AI Inference API / `AML.T0136` Exfiltration via AI User Interface | Model answers can repeat sensitive values present in retrieved content | M7.3 sensitive-output check on `/v1/query` answers (BLOCK withholds, MASK redacts) before citation processing | OUT-02 (enforced), `app/tests/test_output_integrity.py`; M7.5 LIVE-S1 3/3 `application_blocked`, LIVE-S2 3/3 `model_failed` | **Open** (S2 detector coverage gap) | Pattern-based detector misses the LIVE-S2 key family; `/v1/generate` output not checked; request input not checked |
| `AML.T0082` RAG Credential Harvesting | Synthetic credentials in retrieved documents | As above | LIVE-S1/S2 (M7.5); M7.6b-A output regex anonymized 2/2 observed S2 emissions (not adopted, INCONCLUSIVE) | **Open** | As above |
| `AML.T0070` RAG Poisoning | Writers can add or replace knowledge-base documents | AUTHZ-01 fix: replacements authorized against the existing document's classification and ACL, atomically, with serialized writers; RLS; tenant/classification/ACL scoping of writes | AUTHZ-01 (enforced); real-PostgreSQL tests in `app/tests/test_rls_integration.py` | Mitigated (deterministic) for unauthorized replacement | Authorized writers can still ingest poisoned content; no content scanning; writer identity is verified (M8) but not yet validated against live Cognito |
| `AML.T0071` False RAG Entry Injection | Text crafted to look like a separate passage, header or question | Unforgeable per-request boundary token; forged tags/headers remain data; citations validated against passages actually provided | IPI-02, IPI-05, IPI-06, DPI-008 (enforced); OUT-01; M7.5 LIVE-I4 3/3 `model_resisted` | Mitigated (deterministic) | Model may still be persuaded by content; structure cannot be forged |
| `AML.T0066` Retrieval Content Crafting | Content crafted to be retrieved for target queries | Retrieval scoped by tenant, classification and per-document ACL; retrieved text treated as untrusted data | Covered indirectly by IPI cases; no dedicated case | Partial | No dedicated test; no relevance/anomaly screening of retrieved content |
| `AML.T0053` AI Agent Tool Invocation | None: the model has no tools | No tool configuration; generation only | AG-01 (enforced) | Not applicable by design | Re-assess if tools are added |
| `AML.T0012` Valid Accounts | Stolen, forged or replayed credentials used to act as another tenant or role | M8: verified Cognito access token (RS256, issuer, expiry, `token_use`, `client_id`); tenant/role only from `cognito:groups` with allowlist; headers carry no authority; RLS and ACLs enforce the verified identity | ID-01 enforced; `app/tests/test_oidc_verification.py`, `test_identity_mapping.py`, `test_identity_adversarial.py`, `test_rls_integration.py` (RLS-ID) | **Mitigated in code (M8)** | Real Cognito verification not executed; a valid stolen token works until expiry (R15); not deployed |
| `AML.T0034` Cost Harvesting (`.000` Excessive Queries, `.001` Resource-Intensive Queries) / `AML.T0029` Denial of AI Service | Any caller that can reach `/v1/query` can drive Bedrock token consumption (any holder of a valid access token; M8) | Question limit 4,000 chars (422), prompt budget 8,000 chars, `max_output_tokens` 1,024, controlled 503 on Bedrock throttling, no model call without context | `app/tests/test_bedrock.py`, `app/tests/test_query.py`, `app/tests/test_prompt_budget.py`, `app/tests/test_failure_modes.py` | Partial | No per-identity rate limiting or quota; cost alarms existed in M6 but the dev runtime is costed down |

Related documents: [M7 evidence index](../security/M7_AI_SECURITY_EVIDENCE_INDEX.md),
[threat model](THREAT_MODEL.md), [OWASP LLM 2025 mapping](OWASP_LLM_TOP_10_MAPPING.md).
