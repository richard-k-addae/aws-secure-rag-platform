"""Tenant context resolution from verified identity (M8, closes ID-01).

Tenant and role are derived only from a verified Cognito access token:

    Authorization: Bearer <token> -> OidcVerifier -> VerifiedPrincipal
        -> map_principal (admin-managed cognito:groups) -> TenantContext

No header, body field, query parameter, username or unverified claim can set
or change the tenant or role. The TenantContext contract is unchanged, so
route authorization, document ACLs and PostgreSQL row-level security
downstream are untouched.

Responses are generic: 401 "Not authenticated" (with WWW-Authenticate:
Bearer), 403 "Forbidden" for identities that do not map to exactly one
allowed tenant and role, 503 "Authentication unavailable" when verification
cannot be completed. Only bounded reasons are logged or counted.
"""
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth import oidc
from app.auth.permissions import (
    Action,
    Classification,
    Role,
    allowed_classifications,
    is_allowed,
)
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.telemetry import record_security_event

logger = get_logger(__name__)

TENANT_GROUP_PREFIX = "tenant:"
ROLE_GROUP_PREFIX = "role:"

# Documents the scheme in OpenAPI; auto_error=False so every failure goes
# through the bounded error contract below instead of FastAPI's default.
bearer_scheme = HTTPBearer(auto_error=False, description="Cognito access token")


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    role: Role
    allowed_classifications: frozenset[Classification]

    def may(self, action: Action) -> bool:
        return is_allowed(self.role, action)


class IdentityMappingError(Exception):
    """A verified identity does not map to exactly one allowed tenant and role."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def map_principal(
    principal: oidc.VerifiedPrincipal, allowed_tenants: frozenset[str]
) -> TenantContext:
    """Derive TenantContext from verified, admin-managed group membership.

    Exactly one ``tenant:<id>`` group (also present in the server allowlist)
    and exactly one ``role:<role>`` group are required; other groups are
    ignored. Anything else is denied.
    """
    if principal.groups is None:
        raise IdentityMappingError("identity_mapping_denied")
    tenants = [
        g[len(TENANT_GROUP_PREFIX) :] for g in principal.groups if g.startswith(TENANT_GROUP_PREFIX)
    ]
    roles = [
        g[len(ROLE_GROUP_PREFIX) :] for g in principal.groups if g.startswith(ROLE_GROUP_PREFIX)
    ]
    if len(tenants) != 1 or len(roles) != 1 or not tenants[0] or not roles[0]:
        raise IdentityMappingError("identity_mapping_denied")
    tenant_id = tenants[0]
    if tenant_id not in allowed_tenants:
        raise IdentityMappingError("unknown_tenant")
    try:
        role = Role(roles[0])
    except ValueError as exc:
        raise IdentityMappingError("unknown_role") from exc
    return TenantContext(
        tenant_id=tenant_id,
        role=role,
        allowed_classifications=allowed_classifications(role),
    )


def _unauthenticated(reason: str) -> HTTPException:
    record_security_event(reason)
    logger.info("authentication_rejected", reason=reason)
    return HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _unavailable(reason: str) -> HTTPException:
    record_security_event(reason)
    logger.warning("authentication_unavailable", reason=reason)
    return HTTPException(status_code=503, detail="Authentication unavailable")


def resolve_tenant_context(
    settings: Annotated[Settings, Depends(get_settings)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> TenantContext:
    """Authenticate the caller and derive its TenantContext, or fail closed."""
    if credentials is None:
        # No Authorization header, or one that is not a Bearer credential.
        raise _unauthenticated(oidc.AuthFailure.MISSING_TOKEN.value)
    verifier = oidc.get_oidc_verifier()
    if verifier is None:
        raise _unavailable("auth_not_configured")
    try:
        principal = verifier.verify(credentials.credentials)
    except oidc.AuthenticationError as exc:
        raise _unauthenticated(exc.reason.value) from None
    except oidc.AuthenticationUnavailableError as exc:
        raise _unavailable(exc.reason) from None
    try:
        return map_principal(principal, settings.tenant_allowlist_values)
    except IdentityMappingError as exc:
        record_security_event(exc.reason)
        logger.info("identity_mapping_denied", reason=exc.reason)
        raise HTTPException(status_code=403, detail="Forbidden") from None


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
