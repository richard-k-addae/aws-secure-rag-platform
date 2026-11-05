# identity-eval (M8.5) — temporary Cognito evaluation stack

Purpose: validate the production JWT verifier (`app/auth/oidc.py`) against real
Cognito-issued access tokens. **Not** part of the dev or production stack.

## Isolation

- Separate Terraform root with **local, gitignored state**; never the shared
  dev state bucket.
- Creates only: 1 user pool (Lite tier), 6 groups, 2 public app clients.
- No VPC, ECS, RDS, IAM, KMS or Secrets Manager resources; no data sources over
  existing infrastructure.
- `allowed_account_ids` refuses any account other than `expected_account_id`;
  the region is pinned to `us-east-1`.
- The harness has its own, independent guard (see "Account guard" below).
- Synthetic users are **not** managed by Terraform, so no password ever reaches
  state. The harness creates, uses and deletes them.

## Credentials and account guard

Both Terraform and the harness must run with **temporary, role-scoped
credentials**, never an administrator's long-lived keys.

- Terraform has no credential configuration, so a bare `terraform` command uses
  the default AWS chain, and `allowed_account_ids` only checks the *account*, not
  the credential type. **Run Terraform only through
  `scripts/identity_eval_terraform.py`** (see "Terraform wrapper" below), which
  refuses anything but a `rag-eval-terraform` role session.
- Resolve temporary credentials once and export them to the process only:
  `AWS_ACCESS_KEY_ID` (an `ASIA...` key), `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN` and, **required for the wrapper**,
  `AWS_CREDENTIAL_EXPIRATION` (ISO 8601 with a timezone, for example
  `2026-11-04T23:05:00+00:00`). See "Obtaining credentials" below. The harness
  additionally wants `AWS_PROFILE` unset, `AWS_SHARED_CREDENTIALS_FILE` and
  `AWS_CONFIG_FILE` pointing at non-existent files, and
  `AWS_EC2_METADATA_DISABLED=true`; the wrapper rebuilds that environment for
  Terraform itself.
- Run `aws sts get-caller-identity` in that same shell first. The ARN must be
  `...:assumed-role/<role>/...`; stop on `:user/` or `:root`.
- Use one role per tool, never the same session for both:
  `rag-eval-terraform` for plan/apply/destroy, `rag-eval-harness` for the harness.

### Terraform wrapper

```text
python scripts/identity_eval_terraform.py plan         --expected-account-id <acct> --expires-on <YYYY-MM-DD> --out m85.tfplan
python scripts/identity_eval_terraform.py plan-destroy --expected-account-id <acct> --expires-on <YYYY-MM-DD> --out m85-destroy.tfplan
python scripts/identity_eval_terraform.py apply        --expected-account-id <acct> --plan <file>.tfplan --plan-sha256 <sha256>
```

Add `--confirm-live` to execute; without it nothing is contacted or run (dry run;
`apply` still verifies the plan hash and archive structure, but its variables can only
be read with Terraform, so that happens at `--confirm-live`). Add `--record <path>` for
a credential-free run record. Only these three operations exist, with no argument
pass-through
(`-target`, `-auto-approve`, `destroy`, `init`, `import` and so on are refused).
Run `terraform init` separately; it needs no AWS credentials.

Before Terraform is invoked it requires, and otherwise exits 4 without running it:

- the Terraform root still has `allowed_account_ids = [var.expected_account_id]`,
  no provider credential/endpoint/assume-role settings, no `module` blocks, and no
  `*.auto.tfvars`, `terraform.tfvars` or override files;
- `apply`: the saved plan's SHA-256 equals `--plan-sha256` (verified on a private
  copy, which is the file applied) and the plan archive is structurally sound: only
  the entries Terraform writes, a single root module, and an embedded configuration
  and lock file identical to the reviewed root. A saved plan is never overwritten by
  `plan`;
- credentials that are temporary (`ASIA...`) with a timezone-aware
  `AWS_CREDENTIAL_EXPIRATION` that leaves at least 20 minutes to plan or 30 minutes
  to apply (and not more than about 12 hours, the longest role session). Missing,
  malformed, timezone-free or expired values are refused, and the lifetime is
  checked again after the identity check, just before the operation;
- `sts:GetCallerIdentity` with exactly those credentials is an assumed-role session
  of `rag-eval-terraform` in `--expected-account-id` (the same check the harness
  uses, in `evaluations/live/aws_identity.py`).

Then every saved plan is read with `terraform show -json` (read-only, no AWS call)
and must satisfy all of: the plan variables name the expected account; the `aws`
provider is the only provider and takes `allowed_account_ids` from
`var.expected_account_id` with no other credential setting; there are no module
calls; and the changes are exactly the nine evaluation Cognito resources, all
`create` (plan) or all `delete` (destroy plan; fewer than nine is allowed after a
partial create), with the evaluation tags, no deletion protection and no client
secret. `apply` is not invoked on a plan that fails this. A newly created plan that
fails it exits 5 ("do not apply"), and its hash is not printed. The account string
inside a plan is never trusted on its own: only the variable and the provider guard
count.

Terraform runs with a rebuilt environment (all inherited `AWS_*` and `TF_*`
variables dropped, empty private credential/config/Terraform-CLI-config files,
metadata service off) and its output is scrubbed of credential values. The `plan`
and `plan-destroy` operations print `plan_verified=create|delete` and the plan's
SHA-256: record it, review the plan, then pass it to `apply`.

Exit codes: 0 success, 1 Terraform failed, 4 refused (not run), 5 new plan failed
verification.

### Obtaining credentials (IAM Identity Center)

The wrapper only accepts exported credentials; a signed-in AWS CLI profile alone is
not enough. With the planned design (an IAM role `rag-eval-terraform` that trusts
the Identity Center administrator role), define a CLI profile that chains from your
SSO profile (`role_arn` plus `source_profile`), then in the shell that will run the
wrapper:

```powershell
aws sso login --profile <sso-profile>
aws configure export-credentials --profile rag-eval-terraform --format powershell | Invoke-Expression
aws sts get-caller-identity   # must show assumed-role/rag-eval-terraform/...
```

`export-credentials` sets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN` and `AWS_CREDENTIAL_EXPIRATION` (ISO 8601 with a timezone). It
prints secrets, so never redirect it to a file or log. A chained role session lasts
at most one hour, so export fresh credentials for each wrapper call (the plan's
SHA-256 pin carries across sessions). This procedure has not been exercised yet
because no role exists. Requirements that follow from the design:

- the Terraform role must be named exactly `rag-eval-terraform`; an Identity Center
  permission set used directly would have an `AWSReservedSSO_...` role name and is
  refused;
- the session name (an e-mail address for Identity Center sessions) is accepted but
  never echoed or recorded.

Limitations: the wrapper guards the supported path only. Running `terraform`
directly, or with an administrator's keys in the shell, bypasses it; the
`allowed_account_ids` safeguard still applies but does not stop a long-lived
identity in the right account. `AWS_CREDENTIAL_EXPIRATION` is supplied by the
caller: AWS enforces the real expiry, so a wrong value can only cause a refusal or
an apply that fails when the session ends, not extend the session.

### Cognito harness

The harness enforces the same guard itself. Both arguments are used on every
invocation, including `--cleanup-only`:

| Argument | Meaning |
| --- | --- |
| `--expected-account-id <12 digits>` | **Required, no default.** The only account the harness may touch. |
| `--expected-role-name <name>` | Role the credentials must be a session of. Default `rag-eval-harness`; set it for another role name (for example an Identity Center permission-set role). |

Before the first Cognito call it runs `sts:GetCallerIdentity` and refuses
(exit code 4, nothing created) unless the caller is an assumed-role session of
the expected role in the expected account. IAM users, the root user, federated
users, other roles or accounts, malformed identities and any STS failure are
refused. `describe_user_pool` must also return an ARN in the expected account and
region. Errors and evidence carry reason codes only: no ARN, account ID, session
name or credentials. The evidence file records the role name and
`account_verified`; note the account type (member or management) in the
milestone evidence document, because the file does not.

## Lifecycle (each step needs its own explicit approval)

1. Read-only preflight: `aws sts get-caller-identity` (assumed-role in the
   expected account) and `aws cognito-idp list-user-pools --max-results 60`
   (confirm nothing unrelated shares the account).
2. `python scripts/identity_eval_terraform.py plan --expected-account-id <acct>
   --expires-on <YYYY-MM-DD> --out m85.tfplan --confirm-live` -> review (expect
   9 to add) -> record the printed `plan_sha256` -> `python
   scripts/identity_eval_terraform.py apply --expected-account-id <acct> --plan
   m85.tfplan --plan-sha256 <sha256> --confirm-live`.
3. `python scripts/validate_live_cognito.py --expected-account-id <acct>
   --user-pool-id <id> --app-client-id <id> --other-client-id <id>
   --confirm-live` (always deletes its users; exits non-zero with
   `INCOMPLETE_CLEANUP` if it cannot prove it). Omit `--confirm-live` for a plan-only
   run that makes no AWS call.
4. The same wrapper with `plan-destroy ... --out m85-destroy.tfplan` -> review
   (expect 9 to destroy) -> `apply` with that plan and its recorded SHA-256.
5. Independent cleanup checks (`list-user-pools` shows no evaluation pool);
   delete `terraform.tfstate*`, `*.tfplan` and the harness manifest directory.

Recovery after an interrupted run (same credentials and guard arguments):
`python scripts/validate_live_cognito.py --expected-account-id <acct> ...
--cleanup-only --run-id <id>` (or `--all-runs` to remove every `m85-eval-` user in
the evaluation pool).

## Saved plans are account-bound

A saved plan embeds `expected_account_id`, the configuration and the lock file.
It cannot be reused for a different account: discard it and run a new
`plan` through the wrapper after changing accounts (the wrapper also refuses to
apply a plan that does not embed the expected account). Plans, `*.tfplan.json`, state,
`*.tfvars` and crash logs are gitignored; `.tf` files, `.terraform.lock.hcl` and
`*.tfvars.example` remain tracked.

Cost: Cognito Lite includes 10,000 MAU free; the harness uses 10 synthetic users.
The `ExpiresOn` tag records when the stack must be gone.
