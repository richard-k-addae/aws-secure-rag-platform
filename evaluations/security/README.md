# AI security test suite (Phase 5)

Independent tests beyond Bedrock Guardrails:

- Indirect prompt injection embedded in uploaded synthetic documents
- System-prompt disclosure attempts
- Retrieval poisoning (malicious content injected at ingestion)
- Unauthorized document access across roles
- Encoded/obfuscated attacks (base64, homoglyphs, split payloads)
- Token-exhaustion and cost-abuse patterns

Each test asserts an expected control response (block, refusal, masking,
authorization denial) and runs as a CI gate: the pipeline fails when a
control regresses.

## Implementation status

The `expected` values in these case files describe the *intended* control.
They do not assert that the control is implemented. Each case carries a
`control_status` field recording what is actually verified today.

### `sensitive_data_cases.json` - `control_status: detection_only`

`evaluations/tests/test_sensitive_data.py` executes all cases against
`app.core.sensitive_data` and verifies **detection behavior only**: the
correct pattern fires for each case, `redact()` removes the matched value,
and ordinary questions are not flagged.

Enforcement status since M7.3:

- **Model output is enforced** for `/v1/query`: `app/rag/output_integrity.py`
  runs the detector on every answer, withholding it on a credential or
  national-identifier finding and masking emails with `redact()`. This is
  verified by `app/tests/test_output_integrity.py` and adversarial case
  OUT-02, not by this case file.
- **Request input is not enforced**: no question or ingested document
  containing an SSN or credential is blocked at runtime. These cases are
  request-side, so they stay `detection_only`.
- `/v1/generate` output is not checked, and Bedrock Guardrails are not
  enabled.

The scorecard in `scripts/run_evaluations.py` labels this row
"Sensitive-data detection (library)". A tripwire test fails if a case is
promoted beyond `detection_only` without request-side enforcement gates
being added, so the suite cannot silently vouch for a control it does not
exercise. The tripwire is a documentation check, not a code check: whoever
adds request-side enforcement must update `control_status` by hand.

### `adversarial_cases.json`

Executed by `evaluations/tests/test_adversarial_offline.py`, with
`control_status` in `enforced`, `not_implemented` (strict expected failure)
or `characterization`. These are structural, deterministic checks; they make
no claim about live model behavior.
