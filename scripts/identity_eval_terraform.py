"""Fail-closed Terraform wrapper for the M8.5 identity-eval root.

  python scripts/identity_eval_terraform.py plan --expected-account-id <acct> \
      --expires-on YYYY-MM-DD --out m85.tfplan [--confirm-live]
  python scripts/identity_eval_terraform.py plan-destroy --expected-account-id <acct> \
      --expires-on YYYY-MM-DD --out m85-destroy.tfplan [--confirm-live]
  python scripts/identity_eval_terraform.py apply --expected-account-id <acct> \
      --plan m85.tfplan --plan-sha256 <sha256> [--confirm-live]

Run it with temporary credentials of role rag-eval-terraform exported as
AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN and
AWS_CREDENTIAL_EXPIRATION (ISO 8601 with a timezone; required). See
infrastructure/environments/identity-eval/README.md and evaluations/live/terraform_runner.py.
Never part of CI.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evaluations.live.terraform_runner import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
