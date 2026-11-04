# ADR 0003: Fail closed on retrieval and validation errors

Status: Accepted (implemented for store outage, throttling, no-context, and invalid/uncited answers since M7.3; no guardrail layer - Guardrails not adopted, see ADR 0005)

## Context
When a safety-relevant dependency fails, the service must not silently fall
back to ungrounded model output.

## Decision
Retrieval failure or empty context returns a controlled error/refusal and the
model is not called. Guardrail-layer failure (when integrated) is
profile-dependent: `prod` fails closed; `dev`/`test` degrade with an explicit
warning and a structured log event, so development remains usable while the
production posture stays strict.

## Alternatives
Fail open with warnings everywhere (rejected for prod: converts an
infrastructure fault into a safety fault).

## Consequences
Availability is traded for integrity in production; the trade is explicit in
FAILURE_MODES.md and enforced by tests.

## Security impact
Prevents the highest-severity silent failure: confident, uncited answers.

## Cost impact
None.
