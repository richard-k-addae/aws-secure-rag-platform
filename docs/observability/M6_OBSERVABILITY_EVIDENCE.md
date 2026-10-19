# Milestone 6 Evidence: Operational Depth — OpenTelemetry, AWS Metrics, Dashboards & Alarms

This document records the controls, instrumentation, supply-chain evidence, and live AWS verification
established across **Milestone 6 (Operational depth: OpenTelemetry, security metric emission, CloudWatch
dashboards and alarms)**. It supersedes no prior milestone document; it consolidates and cross-references
evidence already recorded in [`docs/security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md`](../security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md)
and [`infrastructure/modules/observability/README.md`](../../infrastructure/modules/observability/README.md),
and adds the M6.5A/M6.5B/M6.6 read-only verification performed directly against live AWS resources.

Every factual claim below is grounded in one of: application source code, Terraform/collector configuration
source, an existing milestone evidence document, or a read-only AWS CLI / Terraform query executed during
this milestone. Where evidence could not be directly observed, this is stated explicitly rather than assumed.

**Evidence as of:** 2026-10-19, repository `m6/observability` @ `1d4f6d872ed89b9b0b7fb468080322441d8098e4`
(clean working tree at time of evidence collection).

---

## 1. Scope

In scope for this document:

- M6.1 — OpenTelemetry SDK foundation (vendor-neutral, off-by-default, fail-closed on content).
- M6.2 — RAG/security/application instrumentation (bounded attributes, privacy-safe metrics).
- M6.3 — Local Prometheus/Grafana observability stack (developer-facing, not deployed to AWS).
- M6.4 — Patched ADOT Collector supply chain and first live AWS metrics deployment.
- M6.5A — `rag.security.events` dimension fix (role-less event support) and live validation.
- M6.5B — CloudWatch dashboard and alarms (actions disabled, no SNS attachment).

Out of scope (explicitly not claimed or delivered by this document):

- Production SLOs or committed latency/availability targets.
- Alarm notification (SNS) enablement.
- AMP, AMG, X-Ray, or any additional paid observability service.
- Any new VPC endpoint, NAT, public ingress, or IAM widening.
- Cosign/signing of the ADOT image (explicitly not configured — see §6).

---

## 2. Architecture Summary

```
FastAPI app (in-process OTel SDK)
   │  OTLP/HTTP, localhost:4318 only (loopback, no SG ingress)
   ▼
ADOT Collector sidecar (ECS task, same task ENI)
   │  awsemf exporter
   ▼
CloudWatch Logs (EMF) — dedicated log group, customer-managed KMS key
   │  PutLogEvents over private VPC "logs" interface endpoint
   ▼
CloudWatch Metrics — namespace "SecureRAGPlatform"
   │
   ├─► CloudWatch Dashboard: rag-platform-dev-observability (M6.5B)
   └─► CloudWatch Alarms: 4 alarms, actions_enabled=false (M6.5B)
```

Key architectural facts (source: `infrastructure/modules/observability/README.md`):

- The application never speaks a backend-specific protocol. It only emits OTLP. The collector decides the
  destination (CloudWatch EMF in AWS; Prometheus locally for M6.3).
- `AOT_CONFIG_CONTENT` delivers the rendered collector config in-memory (no file written to disk), which
  allows the collector container to run with `readonlyRootFilesystem = true`.
- No new VPC endpoints, NAT gateways, or public ingress were introduced by any M6 sub-phase. The OTLP
  receiver listens on loopback only; there is zero security-group ingress on ports 4318/13133.
- `service.instance.id` is explicitly stripped by a `resource` processor (`action: delete`) in both the AWS
  (`adot-collector-config.yaml.tpl`) and local (`observability/otel-collector/config.yaml`) collector
  configurations, for cardinality control.
- `NoDimensionRollup` is configured, so CloudWatch does not synthesize additional rolled-up dimension sets
  beyond what is explicitly declared.
- `error.type` is deliberately excluded from metric dimensions (a documented cost/cardinality decision,
  "Decision A" in the module README) — available via CloudWatch Logs Insights queries on the EMF log
  records instead of as a metric dimension.
- `trace_id`/`span_id` presence inside EMF records is **explicitly UNVERIFIED** per the module README. This
  document does not claim trace/log correlation is available, and no Logs Insights workflow should be
  designed around it until live evidence proves otherwise.

---

## 3. Metric Catalog (Source of Truth: `adot-collector-config.yaml.tpl`)

The following `metric_declarations` are transcribed verbatim from
[`infrastructure/modules/observability/templates/adot-collector-config.yaml.tpl`](../../infrastructure/modules/observability/templates/adot-collector-config.yaml.tpl).
No dimension set is paraphrased or inferred.

| Metric name | Declared dimension sets | Metric name selector |
|---|---|---|
| `http.server.request.duration` | `[http.route, http.request.method, http.response.status_code]` | `^http\.server\.request\.duration$` |
| `rag.query.duration` | `[outcome, role]` | `^rag\.query\.duration$` |
| `rag.query.retrieved_chunks` | `[role]` | `^rag\.query\.retrieved_chunks$` |
| `rag.retrieval.duration` | `[operation, outcome]` | `^rag\.retrieval\.duration$` |
| `rag.retrieval.results` | `[operation, outcome]` | `^rag\.retrieval\.results$` |
| `db.client.operation.duration` | `[operation, outcome]` | `^db\.client\.operation\.duration$` |
| `gen_ai.client.operation.duration` | `[operation, model, outcome]` | `^gen_ai\.client\.operation\.duration$` |
| `gen_ai.client.token.usage` | `[operation, model, token.type]` | `^gen_ai\.client\.token\.usage$` |
| `rag.ingest.duration` | `[classification, outcome]` | `^rag\.ingest\.duration$` |
| `rag.ingest.chunks` | `[classification, outcome]` | `^rag\.ingest\.chunks$` |
| `rag.security.events` | `[event]` **and** `[event, role]` (dual declaration, M6.5A fix) | `^rag\.security\.events$` |

### 3.1 Live-verified status (read-only `aws cloudwatch list-metrics --namespace SecureRAGPlatform`, 2026-10-19)

| Metric | Status | Live series observed |
|---|---|---|
| `rag.security.events` | **LIVE VERIFIED** | 14 series (9 event-only + 5 event+role combinations) |
| `db.client.operation.duration` | **LIVE VERIFIED** | 2 series: `operation=upsert,outcome=success`; `operation=search,outcome=success` |
| `gen_ai.client.token.usage` | **LIVE VERIFIED** | 2 series: input/output token types, `model=us.anthropic.claude-sonnet-4-6`, `operation=chat` |
| `gen_ai.client.operation.duration` | **LIVE VERIFIED** | 2 series: chat (Claude Sonnet) and embeddings (Titan v2) |
| `http.server.request.duration` | **LIVE VERIFIED** | 1 series: `POST /v1/query` → 200 |
| `rag.ingest.chunks` | **LIVE VERIFIED** | 1 series: `classification=internal,outcome=success` |
| `rag.ingest.duration` | **LIVE VERIFIED** | 1 series: `classification=internal,outcome=success` |
| `rag.retrieval.duration` | **LIVE VERIFIED** | 2 series: `operation=search,outcome=hit`; `operation=search,outcome=empty` |
| `rag.retrieval.results` | **LIVE VERIFIED** | 2 series: same as above |
| `rag.query.duration` | **LIVE VERIFIED** | 2 series: `role=reader,outcome=answered`; `role=reader,outcome=no_context` |
| `rag.query.retrieved_chunks` | **LIVE VERIFIED** | 1 series: `role=reader` |

All 11 declared metric names have at least one live CloudWatch series. See §9 for the important distinction
between "a series exists in `list-metrics`" and "the metric has received data recently" — CloudWatch retains
metric listings for an extended period after the last datapoint, so presence in `list-metrics` does not by
itself establish recent or continuous emission.

---

## 4. Security Event Vocabulary (Source: application code, grep-verified)

The complete, closed vocabulary of 9 security event names is defined as a `frozenset` in
[`app/core/telemetry.py`](../../app/core/telemetry.py) (`SECURITY_EVENT_NAMES`). No event name outside this
set can be emitted; the recording function rejects unknown names. Every call site was located and inspected
directly in source.

| Event | Call site(s) | Role supplied? | Behavior notes |
|---|---|---|---|
| `missing_tenant` | `app/auth/tenancy.py` | No | Fires before tenant/role resolution; no `Role` value exists yet at this point in the request lifecycle. |
| `unknown_tenant` | `app/auth/tenancy.py` | No | Same reason — tenant resolution fails prior to role resolution. |
| `unknown_role` | `app/auth/tenancy.py` | No | The role string presented by the caller failed to parse into a known `Role` enum member. |
| `action_denied` | `app/auth/tenancy.py` (`require()` dependency) | Yes (`context.role.value`) | Authorization dependency; role is already resolved at this point. |
| `classification_denied` | `app/api/routes/documents.py` | Yes (role + `classification` attribute) | Document classification gate. |
| `path_rejected` | `app/api/routes/documents.py` | Yes | Path/traversal rejection on document routes. |
| `prompt_too_large` | `app/api/routes/query.py` — **two call sites** (`/query` and `/generate`) | Yes | Both call sites pass the resolved role. |
| `input_sanitized` | `app/core/security.py` (`sanitize_text`) | No | Fires when control characters are stripped from input; no role context is threaded into this low-level sanitization helper. |
| `rls_violation` | `app/rag/retrieval.py` — **two call sites with different role presence** | **Both** (dual-mode) | See §4.1 below — this is the specific defect M6.5A corrected. |

### 4.1 `rls_violation` dual call-site behavior (important correction vs. earlier milestone framing)

Earlier milestone planning documents characterized `rls_violation` as a "roleful" event (i.e., always emitted
with a role dimension). Direct source inspection of `app/rag/retrieval.py` in this milestone disproves that
simplification:

- **Line ~121** — inside the ingest/upsert database-write path. No `TenantContext` is in scope at this call
  site, so `record_security_event("rls_violation")` is called **without** a role argument.
- **Line ~193** — inside the retrieval/query search path. A resolved `TenantContext` is available, so
  `record_security_event("rls_violation", role=context.role.value)` is called **with** a role argument.

Both call sites are triggered by the same underlying condition — a Postgres `InsufficientPrivilege`
(SQLSTATE `42501`) row-level-security violation — surfaced from two different code paths that do not share
an auth context object. This is precisely why the M6.5A dimension fix (`[event]` **and** `[event, role]`,
rather than only `[event, role]`) was required: a single-dimension-set declaration would have silently
dropped metric data for the no-role ingest-path occurrence of this event, which is also the only
**DETERMINISTIC** security alarm defined in M6.5B (§ alarm design, below). This document therefore documents
`rls_violation` as genuinely dual-mode, not as "roleful," to avoid repeating the earlier inaccurate framing.

---

## 5. Privacy / Cardinality Controls

Verified absent from every metric dimension declared in `adot-collector-config.yaml.tpl` and from the EMF
privacy controls documented in the observability module README:

- `tenant_id`, `document_id`, `request_id`, `user_id`
- IP address, raw request path
- Free-form error message / exception text (bounded to `safe_error_type` categories defined in
  `app/core/telemetry.py` — see `AWS_ERROR_CODES` and `EXCEPTION_CLASS_NAMES` frozensets)
- Prompts, answers, retrieved chunks, embeddings
- `DATABASE_URL`, credentials, `db.statement`, raw SQL
- `service.instance.id` (explicitly stripped by the `resource` processor)

All dimension sets use only bounded, enumerable values (event name, role, outcome, operation, classification,
model identifier, HTTP method/route/status code, token type). No dimension set observed in §3 introduces an
unbounded or high-cardinality value.

---

## 6. ADOT Supply-Chain Evidence (M6.4) — Summary and Reconciliation

Full detail is recorded in
[`docs/security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md`](../security/M6_4_ADOT_PATCHED_BUILD_EVIDENCE.md) and
[`tools/adot/README.md`](../../tools/adot/README.md). This section summarizes the facts relevant to ongoing
operational evidence and reconciles one known staleness in the M6.4 document.

- **Upstream rejected:** `aws-observability/aws-otel-collector` `v0.50.0` (commit `7579e0913cc764588c356a61616d6bca021f6b8d`)
  failed the Trivy security gate with 7 unignored HIGH-severity CVEs.
- **Patched build:** Go `1.26.9` toolchain, pinned `golang:1.26` and `alpine:3.21` base images (digest-pinned),
  `FROM scratch` runtime, non-root `aoc` UID `4317`.
- **Patch provenance:** `tools/adot/patches/adot-v0.50.0-security.patch`, SHA-256
  `79F7E2E100EEB483B0367FBC00D5235460BB015BFA31C261846297846B4BC609`, with 10 dependency version bumps and
  documented CVE rationale for each.
- **Reproducibility:** two independent `--no-cache` builds produced bit-for-bit identical `awscollector` and
  `healthcheck` binaries (SHA-256 digests recorded in the M6.4 document).
- **Scan result (authoritative):** Trivy `0.70.0` (pinned digest) — **0 HIGH, 0 CRITICAL**.
- **Signing status:** **NOT CONFIGURED.** Cosign/Signer/Notary signing of the ADOT image is explicitly not
  implemented. This document does not claim any cryptographic signature exists for the deployed image.
- **ECR Basic Scan limitation:** ECR Basic Scan (Clair) cannot scan a `FROM scratch` Go binary image and
  returns `ScanNotFoundException`/`UnsupportedImageError`. This is an expected limitation, not an unresolved
  finding — Trivy, run during the build pipeline, is the authoritative vulnerability gate for this image.
- **Deployed image identifiers:** ECR repository `rag-platform-adot`, tag `v0.50.0-patched.1`, index digest
  `sha256:429737a8f281d09b7bc8b00af0bfe4778ffc31b04be2ba9abdb1aec9147600f7`. Deployed binary hashes were
  confirmed identical to the local reproducible build after an earlier transcription error was identified and
  corrected (documented in the M6.4 evidence as a known process deviation).
- **Known process deviation (M6.4):** one transient `terraform apply -auto-approve` was used once during
  M6.4 to recover from an IAM eventual-consistency circuit-breaker rollback. This is documented in the M6.4
  evidence as a known process deviation and correction; all subsequent applies (M6.5A, M6.5B) used saved
  plans only.

**Reconciliation — task definition revision:** the M6.4 evidence document states that task definition
revision `:4` was the live active service target as of M6.4 closure. As of this document's evidence
collection (2026-10-19, read-only `aws ecs describe-services`), the live service `rag-platform-dev-app` on
cluster `rag-platform-dev` runs task definition revision **`:5`** (`rolloutState = COMPLETED`,
`desiredCount=1`, `runningCount=1`, `pendingCount=0`). Revision `:5` reflects the M6.5A ADOT dimension fix and
the M6.5B ECS service update. The M6.4 document is not altered (it is an accurate historical record as of its
own closure date); this document records the current, superseding state.

---

## 7. AWS Runtime Evidence (current, read-only, 2026-10-19)

| Fact | Value | Source |
|---|---|---|
| AWS account | `376129869231` | prior session evidence, unchanged |
| Region | `us-east-1` | prior session evidence, unchanged |
| ECS cluster | `rag-platform-dev` | `aws ecs describe-services` |
| ECS service | `rag-platform-dev-app` | `aws ecs describe-services` |
| Live task definition | `rag-platform-dev-app:5` | `aws ecs describe-services` (this session) |
| Desired / Running / Pending | 1 / 1 / 0 | `aws ecs describe-services` (this session) |
| Deployment rollout state | `COMPLETED` | `aws ecs describe-services` (this session) |
| CloudWatch namespace | `SecureRAGPlatform` | `aws cloudwatch list-metrics` (this session) |
| Total live metric series (namespace) | 30 | `aws cloudwatch list-metrics` (this session) |
| `rag.security.events` live series | 14 (9 event-only + 5 event+role) | `aws cloudwatch list-metrics` (this session) |
| EMF log group / stream | `/aws/ecs/rag-platform-dev/metrics` / `collector-undefined` | `aws logs describe-log-streams` (this session) |

### 7.1 Dashboard and alarms (M6.5B, applied and live)

| Resource | Status |
|---|---|
| `rag-platform-dev-observability` dashboard | Live, applied via saved plan `tfplan-m6-5b`, 5 added / 0 changed / 0 destroyed |
| `rag-platform-dev-security-rls-violation` alarm | Live, `ActionsEnabled=false`, state OK at last check |
| `rag-platform-dev-running-task-deficit` alarm | Live, `ActionsEnabled=false`, state OK at last check |
| `rag-platform-dev-cpu-high` alarm | Live, `ActionsEnabled=false`, provisional threshold |
| `rag-platform-dev-memory-high` alarm | Live, `ActionsEnabled=false`, provisional threshold |

No SNS topic is attached to any alarm. Existing unrelated topics `cloudwatch-alerts` and `dev-ecs-alarms` were
inspected read-only during M6.5B design and were not attached, per explicit instruction.

---

## 8. Dashboard and Alarm Evidence (M6.5B)

Full design rationale, widget sections (A–H), and alarm classification (DETERMINISTIC / INFRASTRUCTURE
SAFETY / PROVISIONAL / BASELINE-DEPENDENT / NOT RELIABLE YET) were produced during M6.5B design review and
implemented in `infrastructure/environments/dev/dashboard.tf` and `infrastructure/environments/dev/alarms.tf`.
Key facts carried forward here:

- Dashboard labels any percentile widget as an **observed percentile**, not a committed SLO.
- The Security section (G) breaks down `rag.security.events` by `event`, using only the bounded `[event]` /
  `[event, role]` dimension sets established in §3/§4.
- The Database section (E) was included only because `db.client.operation.duration` was live-verified in
  §3.1 at design time; it was not fabricated as a placeholder.
- Four alarms were created, all with `actions_enabled = false`:
  - `security_rls_violation` — DETERMINISTIC (statistic `Sum`, threshold `1`, period `300`, evaluation
    periods `1`, `treat_missing_data = notBreaching`).
  - `ecs_running_task_deficit` — INFRASTRUCTURE SAFETY (metric math equivalent to
    `IF(desired > 0, desired - running, 0) >= 1`, using `AWS/ECS` `ContainerInsights` `RunningTaskCount` /
    `DesiredTaskCount` for the exact cluster/service dimensions).
  - `ecs_cpu_high` / `ecs_memory_high` — PROVISIONAL (threshold `80`, period `300`, evaluation periods `3`,
    `datapoints_to_alarm = 3`, `treat_missing_data = missing`), explicitly labeled provisional pending
    baseline in their alarm descriptions.
- `CKV_AWS_319` Checkov skips (one per alarm) are recorded with justification that notification actions are
  intentionally disabled pending an approved SNS destination — not a missed control.

---

## 9. Baseline Maturity (read-only CloudWatch query, 2026-10-19)

This section distinguishes **infrastructure-level** metric continuity from **application-level** metric
continuity, because they differ substantially and conflating them would overstate baseline readiness.

### 9.1 Infrastructure metrics (`AWS/ECS`, `ClusterName=rag-platform-dev`, `ServiceName=rag-platform-dev-app`)

`CPUUtilization` SampleCount, queried daily (period=86400) for the preceding 9 days:

| Day (UTC-4) | Datapoint count (≈1/min expected = 1440) |
|---|---|
| 2026-10-10 | 1275 (partial — task start day) |
| 2026-10-11 | 1442 |
| 2026-10-12 | 1445 |
| 2026-10-13 | 1442 |
| 2026-10-14 | 1440 |
| 2026-10-15 | 1440 |
| 2026-10-16 | 1440 |
| 2026-10-17 | 1440 |
| 2026-10-18 | 1440 |
| 2026-10-19 | 2 (partial — query time) |

**Classification: PARTIAL.** Infrastructure-level metrics (CPU, Memory, task counts via Container Insights)
have near-continuous, dense (per-minute) data for **9 consecutive days** as of this evidence collection. This
is below the user-specified 14-day minimum baseline window (§10) but demonstrates the collection pipeline is
reliable and continuous for infrastructure signals. No gaps were observed in the queried range.

### 9.2 Application / custom metrics (namespace `SecureRAGPlatform`)

Querying `rag.query.duration` (`role=reader,outcome=answered`), `http.server.request.duration`
(`POST /v1/query 200`), and `gen_ai.client.token.usage` (`token.type=input`, Claude Sonnet, chat) over a
90-day window with daily SampleCount granularity returns data on **exactly one day** — 2026-10-13 (UTC),
with 2 datapoints each. `rag.security.events` (`event=rls_violation`, event-only dimension) similarly shows a
single datapoint (Sum=2) on 2026-10-13.

**Classification: SPARSE / synthetic-validation-only.** Application-level custom metrics show no evidence of
continuous or organic traffic. The data present corresponds to the known M6.4 live smoke test and/or the
M6.5A/M6.5B bounded synthetic security-event validation windows, not day-over-day application usage. The
30 total live series reported by `list-metrics` (§3.1) should not be read as "30 actively-updating series" —
CloudWatch retains metric listings well beyond the window in which data was actually published. This document
does not claim ongoing application traffic exists; it records only what was directly observed.

### 9.3 EMF log stream (`collector-undefined`)

The single EMF log stream in the metrics log group has `firstEventTimestamp` 2026-10-13T05:14:06Z and
`lastEventTimestamp` 2026-10-14T02:55:17Z — a span of roughly 21h41m, entirely consistent with §9.2's finding
that all observed application-level metric data originates from a single validation window, not continuous
operation. No events have been written to this stream in the ~5.8 days preceding this evidence collection.

---

## 10. Baseline Collection Strategy

Per explicit instruction, no production SLOs are defined in this document. The baseline strategy is:

- **Minimum window:** 14 consecutive days of metric collection before any threshold is treated as
  evidence-backed rather than provisional.
- **Extended window:** up to 30 days if traffic remains sparse, to build confidence in percentile stability
  before any future SLO conversation.
- **Synthetic vs. natural traffic:** this document explicitly does **not** label the single-day burst
  identified in §9.2/§9.3 as "natural" traffic. It is consistent with known synthetic validation activity
  performed during M6.4/M6.5A/M6.5B. No natural/organic traffic window has yet been observed for
  application-level metrics. Infrastructure-level metrics (§9.1) are continuous because the ECS task itself
  runs continuously, independent of whether the application receives requests.
- **Action required before a meaningful baseline exists:** either (a) sustained synthetic load over the
  14–30 day window, clearly labeled as synthetic in any future evidence document, or (b) organic usage,
  which should be distinguished from synthetic load by cross-referencing deployment/test-session timestamps
  against metric datapoint timestamps, as done in this document.

---

## 11. Threshold Status Summary

| Alarm | Classification | Status |
|---|---|---|
| `security_rls_violation` | DETERMINISTIC | Enabled, actions disabled, not threshold-sensitive to baseline (fires on any occurrence ≥1) |
| `ecs_running_task_deficit` | INFRASTRUCTURE SAFETY | Enabled, actions disabled, not threshold-sensitive to baseline |
| `ecs_cpu_high` | PROVISIONAL | Enabled, actions disabled, threshold (80%) explicitly labeled provisional pending baseline |
| `ecs_memory_high` | PROVISIONAL | Enabled, actions disabled, threshold (80%) explicitly labeled provisional pending baseline |
| RAG query / retrieval / GenAI latency alarms | BASELINE-DEPENDENT | **Not created.** Insufficient data per §9.2 to set an evidence-backed threshold. |
| No-context rate, security event rate, token usage anomaly alarms | BASELINE-DEPENDENT | **Not created.** Same reason. |
| Telemetry silence / heartbeat alarm | NOT RELIABLE YET | **Not created.** No heartbeat metric exists; the workload is intentionally idle/ephemeral, so absence of data is expected and not alarm-worthy. |

---

## 12. Known Limitations

- **`collector-undefined` log stream name:** the `awsemf` exporter's `log_stream_name: "collector-{TaskId}"`
  template currently resolves to the literal stream name `collector-undefined` rather than substituting an
  actual ECS task ID. This is tracked as an operational risk only (does not affect metric correctness,
  dashboard rendering, or alarm evaluation) and was deliberately not fixed in M6.5A/M6.5B pending root-cause
  confirmation. See the M6.5B design review for the current hypothesis (missing ECS resource-detector
  metadata or an unsupported ADOT placeholder token) — this remains unproven and is not re-investigated in
  this document.
- **Sparse application-level baseline (§9.2):** no production SLO, percentile threshold, or anomaly alarm can
  be responsibly set today. This is the primary blocker to closing the BASELINE-DEPENDENT alarm category.
- **No signing on the ADOT image (§6):** supply-chain integrity today relies on reproducible builds and a
  pinned Trivy scan, not a cryptographic signature. This is an accepted, explicitly-stated gap, not an
  oversight.
- **`trace_id`/`span_id` correlation unverified:** per §2, no claim is made that EMF records are correlatable
  to trace spans. Any future Logs Insights workflow proposing such correlation must independently verify this
  with live evidence first.
- **Top-level `README.md` milestone table staleness:** prior to this document, the repository root
  `README.md` listed Milestone 6 as "Planned." This has been corrected to point at this evidence document
  (see commit diff); the Milestone 5 row was left untouched as out of scope for this milestone's evidence
  package.
