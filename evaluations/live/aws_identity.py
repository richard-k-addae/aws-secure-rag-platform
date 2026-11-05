"""Shared fail-closed AWS caller-identity check for the M8.5 evaluation tooling.

Used by both the Cognito harness and the Terraform execution wrapper so the two
cannot drift. Reason codes only: the observed ARN, account and session name are
never echoed, logged or stored.
"""

from __future__ import annotations

import re
from typing import Any

ACCOUNT_ID_PATTERN = r"[0-9]{12}"
ROLE_NAME_PATTERN = r"[A-Za-z0-9+=,.@_-]{1,64}"
# Only an STS role session qualifies: IAM users (long-lived keys), the root user and
# federated users are refused.
ASSUMED_ROLE_ARN = re.compile(
    rf"arn:aws:sts::(?P<account>{ACCOUNT_ID_PATTERN}):assumed-role/"
    r"(?P<role>[A-Za-z0-9+=,.@_-]{1,64})/(?P<session>[A-Za-z0-9+=,.@_-]{2,64})"
)


class IdentityGuardError(Exception):
    """The caller is not the expected role session; carries a reason code only."""


def verify_assumed_role(sts_client: Any, *, account_id: str, role_name: str) -> dict[str, Any]:
    """Fail closed unless the credentials are a ``role_name`` session in ``account_id``."""
    try:
        identity = sts_client.get_caller_identity()
        account, arn = identity["Account"], identity["Arn"]
    except Exception:
        raise IdentityGuardError("account guard: caller identity unavailable") from None
    match = ASSUMED_ROLE_ARN.fullmatch(arn) if isinstance(arn, str) else None
    if match is None:
        raise IdentityGuardError("account guard: credentials are not an assumed-role session")
    if not (account == match["account"] == account_id):
        raise IdentityGuardError("account guard: credentials belong to a different account")
    if match["role"] != role_name:
        raise IdentityGuardError("account guard: unexpected role")
    return {"account_verified": True, "credential_type": "assumed-role", "role": match["role"]}
