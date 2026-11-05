"""Verified cognito:groups -> TenantContext (M8).

Tenant and role come only from verified, admin-managed groups: exactly one
``tenant:<id>`` (also on the server allowlist) and exactly one ``role:<role>``.
"""
import pytest

from app.auth.oidc import VerifiedPrincipal
from app.auth.permissions import Role, allowed_classifications
from app.auth.tenancy import IdentityMappingError, TenantContext, map_principal

ALLOWED = frozenset({"tenant-a", "tenant-b"})


def principal(groups: tuple[str, ...] | None) -> VerifiedPrincipal:
    return VerifiedPrincipal(sub="synthetic-sub", client_id="test-app-client", groups=groups)


@pytest.mark.parametrize(
    ("groups", "tenant", "role"),
    [
        (("tenant:tenant-a", "role:reader"), "tenant-a", Role.READER),
        (("role:ingestor", "tenant:tenant-b"), "tenant-b", Role.INGESTOR),
        (("tenant:tenant-a", "role:admin", "ops-team", "Everyone"), "tenant-a", Role.ADMIN),
    ],
)
def test_one_tenant_and_one_role_group_map_to_context(
    groups: tuple[str, ...], tenant: str, role: Role
) -> None:
    assert map_principal(principal(groups), ALLOWED) == TenantContext(
        tenant_id=tenant, role=role, allowed_classifications=allowed_classifications(role)
    )


@pytest.mark.parametrize(
    ("groups", "reason"),
    [
        (("tenant:tenant-a", "tenant:tenant-b", "role:reader"), "identity_mapping_denied"),
        (("tenant:tenant-a", "role:reader", "role:admin"), "identity_mapping_denied"),
        (("tenant:tenant-a", "role:reader", "role:reader"), "identity_mapping_denied"),
        (("role:reader",), "identity_mapping_denied"),
        (("tenant:tenant-a",), "identity_mapping_denied"),
        ((), "identity_mapping_denied"),
        (("tenant:", "role:reader"), "identity_mapping_denied"),
        (("tenant:tenant-a", "role:"), "identity_mapping_denied"),
        (None, "identity_mapping_denied"),
        (("tenant:unknown", "role:reader"), "unknown_tenant"),
        (("tenant:tenant-a", "role:superuser"), "unknown_role"),
        (("tenant:tenant-a", "role:Admin"), "unknown_role"),
        (("Tenant:tenant-a", "role:reader"), "identity_mapping_denied"),
    ],
)
def test_ambiguous_missing_or_unknown_groups_are_denied(
    groups: tuple[str, ...] | None, reason: str
) -> None:
    with pytest.raises(IdentityMappingError) as info:
        map_principal(principal(groups), ALLOWED)
    assert info.value.reason == reason


def test_allowlist_is_enforced_even_for_well_formed_groups() -> None:
    with pytest.raises(IdentityMappingError):
        map_principal(principal(("tenant:tenant-b", "role:reader")), frozenset({"tenant-a"}))


def test_mapping_uses_no_identity_material_besides_groups() -> None:
    a = VerifiedPrincipal(
        sub="admin", client_id="tenant-b", groups=("tenant:tenant-a", "role:reader")
    )
    assert map_principal(a, ALLOWED).tenant_id == "tenant-a"
    assert map_principal(a, ALLOWED).role is Role.READER
