# ADR 0005: Do not adopt the evaluated Bedrock Guardrail configurations

Status: Accepted (M7.7, 2026-11-04)

## Context
Bedrock Guardrails were a stretch goal. M7.6 evaluated them against the
M7.5 no-Guardrails baseline with pre-registered cases, rules and immutable
guardrail versions ([M7.6 comparison](../security/M7_6_GUARDRAILS_COMPARISON.md)):

- **M7.6a** (prompt attack Standard HIGH, output sensitive-information
  masking, Classic contextual grounding 0.70/0.70): 0 unsafe final outcomes,
  but 39/54 requests blocked at input, 5/6 answerable/conflict runs refused,
  a harmless input (G4) blocked 3/3, and LIVE-S2 stopped by the input
  prompt-attack filter rather than the output regex.
- **M7.6b-A** (output sensitive-information policy only): LIVE-S2 final
  exposure 0/3; the custom regex anonymized 2/2 observed emissions; verdict
  INCONCLUSIVE under the pre-registered rule.
- **M7.6b-B** (prompt attack MEDIUM, no grounding): behaviour identical to
  HIGH on every tested case; G4 still blocked 3/3; usability target not met.

## Decision
No tested Bedrock Guardrail configuration is adopted. Nothing is attached to
the application, and there is no IAM or account-level Guardrail enforcement.
The evaluation guardrail was deleted after the evidence was committed; the
committed definitions allow it to be recreated.

Reasons:
- prompt-attack filtering at HIGH over-blocked legitimate and harmless input;
- MEDIUM did not improve usability on the tested cases;
- Classic contextual grounding caused unacceptable refusals of correct,
  cited answers;
- the S2 output regex is promising but inconclusive;
- Standard contextual grounding is deferred until the project's pinned AWS
  tooling supports it.

Application controls remain primary: M7.2 prompt boundaries, M7.3 citation
validation and sensitive-output withholding/redaction, tenant/ACL/RLS
authorization and AUTHZ-01.

This is a deliberate, evidence-based non-adoption decision, not an
unfinished implementation.

## Alternatives
- Adopt M7.6a as configured (rejected: false refusals and false positives).
- Adopt prompt attack at MEDIUM (rejected: no measured usability gain).
- Adopt only the output sensitive-information regex (deferred: inconclusive;
  a future pre-registered run could revisit it as an additional layer behind
  the application detector).

## Consequences
The application sensitive-output detector's S2 coverage gap stays OPEN in
the application. Revisit when Standard contextual grounding is available in
the pinned tooling, or when a pre-registered run exercises the output regex
on enough emissions to reach a verdict.

## Security impact
No change to the runtime security posture; avoids adopting controls whose
measured false-positive cost exceeded their marginal benefit on these cases.

## Cost impact
None (no guardrail is attached or retained).
