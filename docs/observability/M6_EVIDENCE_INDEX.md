# M6 Evidence Index

Maps each Milestone 6 control/claim to its source, validating artifact, and current verification status.
Use this index to locate the authoritative evidence for any M6 claim without re-deriving it.

| # | Control / Claim | Source (code/config) | Verification artifact | Milestone | Status |
|---|---|---|---|---|---|
| 1 | OTel SDK off by default, fail-closed on content | [`app/core/telemetry.py`](../../app/core/telemetry.py) | Source inspection (this doc, M6.6) | M6.1 | Verified (source) |
| 2 | Span attribute allowlist / exception scrubbing | [`app/core/telemetry.py`](../../app/core/telemetry.py) | Source inspection | M6.1 | Verified (source) |
| 3 | Bounded error categories (`AWS_ERROR_CODES`, `EXCEPTION_CLASS_NAMES`) | [`app/core/telemetry.py`](../../app/core/telemetry.py) | Source inspection | M6.1 | Verified (source) |
| 4 | Security event vocabulary (9 names, closed set) | [`app/core/telemetry.py`](../../app/core/telemetry.py) `SECURITY_EVENT_NAMES` | Source inspection + grep across call sites | M6.1/M6.2 | Verified (source) |
| 5 | `missing_tenant`/`unknown_tenant`/`unknown_role` emitted without role | [`app/auth/tenancy.py`](../../app/auth/tenancy.py) | Source inspection | M6.2 | Verified (source) |
| 6 | `action_denied` emitted with role | [`app/auth/tenancy.py`](../../app/auth/tenancy.py) (`require()`) | Source inspection | M6.2 | Verified (source) |
| 7 | `classification_denied`/`path_rejected` emitted with role | [`app/api/routes/documents.py`](../../app/api/routes/documents.py) | Source inspection | M6.2 | Verified (source) |
| 8 | `prompt_too_large` emitted with role (2 call sites) | [`app/api/routes/query.py`](../../app/api/routes/query.py) | Source inspection | M6.2 | Verified (source) |
| 9 | `input_sanitized` emitted without role | [`app/core/security.py`](../../app/core/security.py) (`sanitize_text`) | Source inspection | M6.2 | Verified (source) |
| 10 | `rls_violation` dual-mode (with and without role) | [`app/rag/retrieval.py`](../../app/rag/retrieval.py) (two call sites) | Source inspection (corrects earlier "roleful only" framing) | M6.2/M6.5A | Verified (source) |
| 11 | Local Prometheus/Grafana stack (dev-only, not AWS) | [`observability/otel-collector/config.yaml`](../../observability/otel-collector/config.yaml), [`observability/prometheus/prometheus.yml`](../../observability/prometheus/prometheus.yml) | Source inspection; `git log` dates to local-stack commit | M6.3 | Verified (source) |
| 12 | ADOT upstream image rejected (7 HIGH CVEs) | [`docs/security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md`](../security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md) | Trivy scan record in M6.4 doc | M6.4 | Verified (prior milestone doc) |
| 13 | Patched ADOT build reproducibility (bit-identical binaries) | [`docs/security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md`](../security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md), [`tools/adot/README.md`](../../tools/adot/README.md) | SHA-256 digests recorded in M6.4 doc | M6.4 | Verified (prior milestone doc) |
| 14 | Patched ADOT Trivy result: 0 HIGH / 0 CRITICAL | [`docs/security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md`](../security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md) | Pinned Trivy `0.70.0` scan record | M6.4 | Verified (prior milestone doc) |
| 15 | ADOT image signing status | [`docs/security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md`](../security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md) | Explicit "NOT CONFIGURED" statement | M6.4 | Verified — gap explicitly disclosed, not a false claim |
| 16 | `rag.security.events` dual dimension declaration `[event]` / `[event, role]` | [`infrastructure/modules/observability/templates/adot-collector-config.yaml.tpl`](../../infrastructure/modules/observability/templates/adot-collector-config.yaml.tpl) | Terraform plan/apply + local OTLP validation (M6.5A) | M6.5A | Verified (config + live) |
| 17 | No sensitive dimensions in any metric declaration | [`infrastructure/modules/observability/templates/adot-collector-config.yaml.tpl`](../../infrastructure/modules/observability/templates/adot-collector-config.yaml.tpl) | Source inspection, this doc §5 | M6.5A/M6.6 | Verified (source) |
| 18 | Live ECS task definition revision | AWS ECS | `aws ecs describe-services` (read-only, 2026-10-19) | M6.5B/M6.6 | Verified (live, `:5`) |
| 19 | `rag.security.events` live in CloudWatch, 14 series | AWS CloudWatch | `aws cloudwatch list-metrics --namespace SecureRAGPlatform` (2026-10-19) | M6.5A/M6.6 | Verified (live) |
| 20 | All 11 declared metric names have ≥1 live series | AWS CloudWatch | `aws cloudwatch list-metrics` (2026-10-19) | M6.4–M6.6 | Verified (live) |
| 21 | `rag-platform-dev-observability` dashboard exists, 1 dashboard added | AWS CloudWatch, [`infrastructure/environments/dev/dashboard.tf`](../../infrastructure/environments/dev/dashboard.tf) | `terraform apply tfplan-m6-5b` summary (5 added/0 changed/0 destroyed); `aws cloudwatch list-dashboards` | M6.5B | Verified (live) |
| 22 | 4 alarms exist, `actions_enabled=false`, no SNS attachment | AWS CloudWatch, [`infrastructure/environments/dev/alarms.tf`](../../infrastructure/environments/dev/alarms.tf) | `aws cloudwatch describe-alarms` (live verification report, M6.5B) | M6.5B | Verified (live) |
| 23 | Post-apply Terraform drift: none | Terraform state | `terraform plan -detailed-exitcode` → exit 0 (M6.5B closure) | M6.5B | Verified (command output) |
| 24 | Checkov baseline: 182 passed / 0 failed / 7 skipped | Checkov | `checkov --framework terraform -d infrastructure --compact` (M6.5B closure) | M6.5B | Verified (command output) |
| 25 | `CKV_AWS_319` skips justified (disabled alarm actions) | [`infrastructure/environments/dev/alarms.tf`](../../infrastructure/environments/dev/alarms.tf) | Inline skip comments + Checkov scan result | M6.5B | Verified (source + command output) |
| 26 | Infrastructure metric continuity: 9 consecutive days | AWS CloudWatch | `aws cloudwatch get-metric-statistics` (`AWS/ECS` `CPUUtilization`, 2026-10-19) | M6.6 | Verified (live, this session) — classified PARTIAL, below 14-day minimum |
| 27 | Application metric continuity: single-day burst only | AWS CloudWatch | `aws cloudwatch get-metric-statistics` (90-day window, 2026-10-19) | M6.6 | Verified (live, this session) — classified SPARSE |
| 28 | `collector-undefined` EMF log stream, single ~21h41m window | AWS CloudWatch Logs | `aws logs describe-log-streams` (2026-10-19) | M6.6 | Verified (live, this session) — open finding, not fixed |
| 29 | No destructive/security-sensitive test data used in live validation | M6.5A/M6.5B session instructions and execution record | Prior session transcript (synthetic, bounded OTLP payloads only) | M6.5A/M6.5B | Verified (process record, not independently re-audited in M6.6) |
| 30 | No production SLO claimed anywhere in M6 documentation | [`M6_OBSERVABILITY_EVIDENCE.md`](./M6_OBSERVABILITY_EVIDENCE.md), [`M6_BASELINE_TEMPLATE.md`](./M6_BASELINE_TEMPLATE.md) | Explicit "not an SLO" labeling throughout both documents | M6.6 | Verified (document review) |

## Evidence Durability Notes

- Items 12–15 (ADOT supply-chain detail) exist only in `docs/security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md`
  and `tools/adot/README.md` — both are durable, committed repository files. No action needed.
- Items 18, 19, 20, 26, 27, 28 were derived from live, read-only AWS CLI queries executed during this M6.6
  session. The raw CLI query transcripts themselves are **not** separately archived as files in this
  repository; only the summarized findings are preserved in `M6_OBSERVABILITY_EVIDENCE.md`. This is **not**
  a blocker to M6 closure: the durable evidence for this milestone is the source-controlled Terraform
  configuration, the committed evidence documents, and the live CloudWatch/ECS state itself (which remains
  independently re-queryable at any time using the exact commands recorded in this index). Archiving
  byte-for-byte raw CLI transcripts for every read-only verification query is a future evidence-retention
  improvement to consider if a stricter audit trail is ever required — it does not change any finding in
  this document and should not be read as an open defect in the M6 evidence package.
- Item 29 (no destructive/security-sensitive test data) relies on the prior M6.5A/M6.5B session record, which
  is not independently re-verified by this document; it is carried forward as a process claim, not re-proven
  here.
