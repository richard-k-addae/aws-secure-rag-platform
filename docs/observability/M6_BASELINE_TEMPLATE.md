# M6 Baseline Observation Template

This is a repeatable template for recording an observation window of live CloudWatch telemetry for the
secure RAG platform. It does not itself contain a completed baseline — see
[`M6_OBSERVABILITY_EVIDENCE.md`](./M6_OBSERVABILITY_EVIDENCE.md) §9 for the current (sparse,
synthetic-validation-only) state as of 2026-10-19.

Copy this template into a new dated file (e.g. `M6_BASELINE_2026-11-02.md`) each time a new observation
window is recorded. Do not edit this template in place to record an observation — keep it reusable.

**Do not use this template to define or imply a production SLO.** Any percentile value recorded here is an
**observed percentile over the stated window**, not a commitment, and must be labeled as such everywhere it
is written down or graphed.

---

## Window Metadata

| Field | Value |
|---|---|
| Window start (UTC) | |
| Window end (UTC) | |
| Window length (days) | |
| Traffic character | `synthetic` / `natural` / `mixed` — state which, and how this was determined (e.g. cross-reference against known deployment/test-session timestamps) |
| ECS task definition revision(s) active during window | |
| Collector image tag/digest active during window | |
| Observer | |
| Evidence collection method | e.g. `aws cloudwatch get-metric-statistics`, read-only |

## Continuity Check (run before trusting any statistic below)

For each metric of interest, confirm data density across the window rather than assuming continuity. Record
day-by-day `SampleCount` (or equivalent) exactly as done in
[`M6_OBSERVABILITY_EVIDENCE.md`](./M6_OBSERVABILITY_EVIDENCE.md) §9, and classify the window as one of:

- **NOT STARTED** — no data in the window.
- **SPARSE** — data exists but is concentrated in short bursts with large gaps; not suitable for threshold
  derivation.
- **PARTIAL** — mostly continuous but below the 14-day minimum, or with some gaps.
- **MATURE** — continuous (no unexplained gaps) for at least 14 days, ideally 30.

| Metric | Dimension(s) queried | Days with data / days in window | Classification |
|---|---|---|---|
| `AWS/ECS` `CPUUtilization` | `ClusterName`, `ServiceName` | | |
| `AWS/ECS` `MemoryUtilization` | `ClusterName`, `ServiceName` | | |
| `rag.query.duration` | `role`, `outcome` | | |
| `rag.retrieval.duration` | `operation`, `outcome` | | |
| `gen_ai.client.operation.duration` | `operation`, `model`, `outcome` | | |
| `rag.security.events` | `event` (+ `role` where applicable) | | |
| `http.server.request.duration` | `http.route`, `http.request.method`, `http.response.status_code` | | |

## Observed Statistics (fill in only for metrics classified PARTIAL or MATURE above)

> Do not derive a threshold recommendation from a metric classified NOT STARTED or SPARSE.

| Metric | Statistic | Observed value | Observed window | Note |
|---|---|---|---|---|
| `rag.query.duration` | p50 (observed, not SLO) | | | |
| `rag.query.duration` | p95 (observed, not SLO) | | | |
| `rag.retrieval.duration` | p50 (observed, not SLO) | | | |
| `rag.retrieval.duration` | p95 (observed, not SLO) | | | |
| `gen_ai.client.operation.duration` | p95 (observed, not SLO) | | | |
| `rag.security.events` | rate per day, by event | | | |
| CPU utilization | mean / max | | | |
| Memory utilization | mean / max | | | |

## Alarm Review for This Window

For each existing alarm, record whether the window's data would have changed its evaluation:

| Alarm | State observed during window | Would a baseline-informed threshold change? |
|---|---|---|
| `rag-platform-dev-security-rls-violation` | | |
| `rag-platform-dev-running-task-deficit` | | |
| `rag-platform-dev-cpu-high` | | |
| `rag-platform-dev-memory-high` | | |

## Decision

State explicitly, for this window only:

- Is the window long enough and continuous enough to promote any BASELINE-DEPENDENT alarm out of that
  category? (Yes/No, and why.)
- Is the window long enough to revisit the PROVISIONAL label on CPU/memory thresholds? (Yes/No, and why.)
- Any newly observed traffic pattern, gap, or anomaly worth carrying into the next window's evidence.

## Explicitly Not Claimed by This Template

- A production SLO.
- Enablement of alarm actions / SNS notification based solely on this window.
- Statistical significance below the stated minimum window length (14 days).
