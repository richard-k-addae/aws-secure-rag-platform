# identity-eval-bootstrap (M8.5) — temporary IAM roles for the Cognito evaluation

Purpose: create the two short-lived-credential roles that M8.5 runs as, so neither
the Terraform wrapper nor the live Cognito harness ever uses an administrator's
long-lived keys. **Not** part of the dev or production stack. **Temporary:**
destroy both roles after M8.5.

| Role | Used by | May do |
| --- | --- | --- |
| `rag-eval-terraform` | `scripts/identity_eval_terraform.py` (the only supported way to run the `identity-eval` root) | Create, read and delete the evaluation user pool, its groups and its app clients. Nothing else. |
| `rag-eval-harness` | `scripts/validate_live_cognito.py` | Inspect the evaluation pool and its clients; create, authenticate, sign out and delete synthetic users; change their group membership. It cannot create or delete pools, groups or clients. |

Both role names are matched exactly by `evaluations/live/aws_identity.py`; do not
rename them.

## What this root creates

Only two IAM roles and their two inline policies (4 resources). No managed
policies, no attachments to other roles, no data sources over existing
infrastructure (the `aws_iam_policy_document` data sources are rendered locally),
no modules, no imports. It never references dev state, dev IAM, ECS, RDS, VPC or
Secrets Manager.

### Permissions

All pool-level actions are limited to
`arn:aws:cognito-idp:us-east-1:<project account>:userpool/*` **and** to pools tagged
`Environment=identity-eval`, `Milestone=M8.5`, `Ephemeral=true` (set at creation by
the `identity-eval` root and required by the harness pool guard).

`rag-eval-terraform` additionally has `cognito-idp:CreateUserPool` and
`cognito-idp:TagResource` on `Resource: "*"`. AWS defines no resource type for
`CreateUserPool` (the pool does not exist yet), so it cannot be ARN-scoped.
`TagResource` was added because Cognito required separate tagging authorization when
Terraform created the pool with its M8.5 tags. Both are bounded by
`aws:RequestedRegion = us-east-1`, the four required request tags
(`Project`, `Environment`, `Milestone`, `Ephemeral`) and `aws:TagKeys` limited to the
six default tag keys. There is no `UntagResource`, no `ListUserPools`, no `Update*`
and no non-Cognito action. `rag-eval-harness` cannot tag or untag.

Residual risk while the role existed: the tag conditions constrain the tags in the
request, not which pool is tagged. So `rag-eval-terraform` could in theory have
given another existing user pool in the same account and region the M8.5 tag set,
bringing it under the tag-scoped statements. The role was temporary, assumable only
with MFA, and was destroyed after the M8.5 validation passed, so this risk is not
active now. It would apply again only if the roles were recreated.

### Trust

Both roles trust exactly one principal, `var.operator_principal_arn` (an IAM user
in the project account; roles are refused), for `sts:AssumeRole` **only when the session was
authenticated with MFA** (`aws:MultiFactorAuthPresent = true`). No wildcard
principal, no external ID, no `sts:TagSession`, no `sts:SetSourceIdentity`.
`max_session_duration` is one hour.

The operator ARN is a plan-time variable. **Never commit it**, and never put a
real ARN in documentation, `*.tfvars` or examples.

## Guards

- `allowed_account_ids = [var.expected_account_id]`: plan and apply fail if the
  credentials resolve to any other account.
- `expected_account_id` must be `376129869231`; `aws_region` must be `us-east-1`.
- `operator_principal_arn` must be `arn:aws:iam::376129869231:user/<name>`: an IAM
  user only. Roles, the root user, wildcards and other accounts are refused.
- The provider carries no credentials, profile, endpoint or `assume_role` block.

## State

Local only (`backend "local"`, `terraform.tfstate` in this directory). It is
gitignored (`*.tfstate*`, `*.tfplan`, `.terraform/`) and holds role ARNs and policy
JSON, no credentials. It never touches the shared dev state bucket. **Keep it until
the destroy is verified**; without it the roles must be removed by hand (see
"Manual recovery").

**Never commit state, plans, `*.tfvars` or credentials.** `.tf` files,
`.terraform.lock.hcl` and this README are the only tracked files.

## Who runs what

```text
authorized IAM operator (long-lived identity, MFA)
    │  this root only: one-time bootstrap apply and final destroy
    │
    ├── MFA-protected sts:AssumeRole ──► rag-eval-terraform ──► temporary STS credentials
    │                                       └── scripts/identity_eval_terraform.py
    └── MFA-protected sts:AssumeRole ──► rag-eval-harness ───► temporary STS credentials
                                            └── scripts/validate_live_cognito.py
```

This bootstrap root itself is applied by the operator: creating IAM roles needs an
IAM-capable identity, and no other one exists. Everything after it runs on
one-hour role sessions. The operator identity remains a long-lived credential
(risks R10/R17); these roles narrow what each tool session can do, they do not
retire it.

Local CLI profiles for the operator (outside the repository, for example in
`~/.aws/config`; the values below are placeholders):

```ini
[profile rag-eval-terraform]
role_arn         = arn:aws:iam::<account>:role/rag-eval-terraform
source_profile   = <operator-profile>
mfa_serial       = arn:aws:iam::<account>:mfa/<device>
duration_seconds = 3600

[profile rag-eval-harness]
role_arn         = arn:aws:iam::<account>:role/rag-eval-harness
source_profile   = <operator-profile>
mfa_serial       = arn:aws:iam::<account>:mfa/<device>
duration_seconds = 3600
```

How to export a role session to the tools is described in
`../identity-eval/README.md` ("Obtaining credentials").

## M8.5 execution order (each step needs its own explicit approval)

1. **Bootstrap plan** (operator): `terraform init`, then `terraform plan` with
   `-var expected_account_id=376129869231 -var operator_principal_arn=<arn>
   -var expires_on=<YYYY-MM-DD>`. Expect exactly **4 to add, 0 to change, 0 to
   destroy** (2 `aws_iam_role`, 2 `aws_iam_role_policy`). Review the rendered trust
   and permissions JSON.
2. **Bootstrap apply** (operator) of the reviewed saved plan.
3. **Preflight** (operator): `aws sts get-caller-identity` and
   `aws cognito-idp list-user-pools --max-results 60` (confirm nothing unrelated
   carries the evaluation tags).
4. **identity-eval plan and apply** as `rag-eval-terraform`, through the wrapper
   (see `../identity-eval/README.md`).
5. **Harness** as `rag-eval-harness` (separate shell, separate session).
6. **identity-eval destroy** as `rag-eval-terraform`: wrapper `plan-destroy`, review,
   `apply`.
7. **Cleanup check** (operator): `list-user-pools` shows no evaluation pool.
8. **Bootstrap destroy** (operator): `terraform plan -destroy -out=<file>.tfplan`,
   expect **4 to destroy**, review, `terraform apply <file>.tfplan`.
9. Delete `terraform.tfstate*`, `*.tfplan` and `.terraform/` here, and remove the two
   local CLI profiles.

## Destroy order

The `identity-eval` stack (step 6) must be destroyed and verified **before** this
root (step 8): `rag-eval-terraform` is the role that deletes the evaluation pool.
The roles are not retained for later evaluations.

## Manual recovery if the local state is lost

Run as the operator, after confirming no evaluation pool remains:

```sh
aws iam delete-role-policy --role-name rag-eval-terraform --policy-name m85-identity-eval-cognito-lifecycle
aws iam delete-role        --role-name rag-eval-terraform
aws iam delete-role-policy --role-name rag-eval-harness   --policy-name m85-identity-eval-cognito-harness
aws iam delete-role        --role-name rag-eval-harness
aws iam list-roles --query "Roles[?starts_with(RoleName, 'rag-eval-')].RoleName"   # expect []
```

If an evaluation pool is still present and the roles are gone, recreate the roles
from this root first (new local state) rather than deleting the pool with an
administrator identity.
