# AI Incident Response Runbook

Covers AI-specific incidents. General infrastructure incidents (service
down, database failure) follow standard ECS/RDS operational procedures.

> **Applicability (M7.7):** steps that reference Bedrock Guardrails,
> Cognito, API Gateway, rate limits, SQS or ingestion-time content
> validation describe the target architecture; none of these is deployed.
> Guardrails were evaluated and not adopted (ADR 0005); identity is
> header-based (ID-01, open). Today, detection relies on application
> signals: `query_answer_withheld` events (bounded `reason`, e.g.
> `sensitive_output`, `uncited`), RAG/Bedrock metrics and logs.

## Severity levels

- SEV1: Confirmed sensitive-data disclosure or successful injection reaching users
- SEV2: Guardrail bypass demonstrated without confirmed user impact; sustained cost abuse
- SEV3: Elevated hallucination/refusal-failure rates; single anomalous events

## Scenario 1: Suspected prompt-injection success

1. Confirm via CloudWatch: guardrail intervention metrics, prompt-attack detections, anomalous output patterns for the request ID.
2. Contain: revoke the requesting identity's tokens in Cognito; if systemic, enable maintenance mode (reject /v1 traffic at API Gateway).
3. Investigate with redacted logs first; enable full-content logging ONLY in the dev environment while reproducing with synthetic equivalents.
4. Eradicate: add the attack pattern to evaluations/security as a failing test; fix; verify the test passes; redeploy.
5. Document in post-incident review; update THREAT_MODEL.md.

## Scenario 2: PII detected in model output

1. Identify scope from PII-detection metrics and affected request IDs.
2. Verify Guardrails PII masking configuration is active and unchanged (CloudTrail config history).
3. Check whether PII originated in an ingested document (ingestion gap) or user input (masking gap); fix at the failing control.
4. Purge affected content from the knowledge base and re-run ingestion validation.
5. Add regression case to the golden dataset.

## Scenario 3: Cost/token abuse

1. Alarm fires on token or estimated-cost threshold.
2. Identify offending identities via per-request token metrics.
3. Throttle or revoke via Cognito; tighten rate limits.
4. Review input size limits and max-token configuration for gaps.

## Scenario 4: Retrieval poisoning suspected

1. Quarantine: pause ingestion queue (SQS) processing.
2. Diff recent ingestions against source documents in S3 (versioned).
3. Remove poisoned vectors by document ID; re-embed from verified sources.
4. Add the poisoning pattern to ingestion-time content validation.

## Post-incident

Every SEV1/SEV2 gets a written review: timeline, root cause, control
gap, added regression tests, threat-model update.
