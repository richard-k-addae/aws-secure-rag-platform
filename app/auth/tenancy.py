"""Tenant context resolution.

Tenant identity is resolved server-side and is never read from the request
body: a caller cannot assert its own tenant. On this branch identity arrives
as request headers validated against a configured allowlist. Milestone 4
replaces the resolver with verified Cognito JWT claims - the TenantContext
contract and every call site stay unchanged.
"""
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException

from app.auth.permissions import (
    Action,
    Classification,
    Role,
    allowed_classifications,
    is_allowed,
)
from app.core.config import Settings, get_settings
from app.core.telemetry import record_security_event


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    role: Role
    allowed_classifications: frozenset[Classification]

    def may(self, action: Action) -> bool:
        return is_allowed(self.role, action)


def resolve_tenant_context(
    settings: Annotated[Settings, Depends(get_settings)],
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-Id")] = None,
    x_tenant_role: Annotated[str | None, Header(alias="X-Tenant-Role")] = None,
) -> TenantContext:
    """Resolve and validate caller identity, or fail closed."""
    if not x_tenant_id:
        record_security_event("missing_tenant")
        raise HTTPException(status_code=401, detail="Missing tenant context")
    if x_tenant_id not in settings.tenant_allowlist_values:
        record_security_event("unknown_tenant")
        raise HTTPException(status_code=403, detail="Unknown tenant")
    try:
        role = Role(x_tenant_role or settings.default_tenant_role)
    except ValueError as exc:
        record_security_event("unknown_role")
        raise HTTPException(status_code=403, detail="Unknown role") from exc
    return TenantContext(
        tenant_id=x_tenant_id,
        role=role,
        allowed_classifications=allowed_classifications(role),
    )


def require(action: Action) -> object:
    """Dependency factory enforcing an action permission."""

    def dependency(
        context: Annotated[TenantContext, Depends(resolve_tenant_context)],
    ) -> TenantContext:
        if not context.may(action):
            record_security_event("action_denied", role=context.role.value)
            raise HTTPException(
                status_code=403,
                detail=f"Role '{context.role.value}' may not perform '{action.value}'",
            )
        return context

    return Depends(dependency)
