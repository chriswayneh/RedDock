import pytest

from app.authorization import (
    LOCAL_AUTHORIZATION,
    ROLE_PERMISSIONS,
    AuthorizationContext,
    AuthorizationDenied,
    Permission,
    Role,
    permissions_for,
)


def test_owner_has_every_named_permission_and_only_owner_can_transfer():
    assert ROLE_PERMISSIONS[Role.OWNER] == frozenset(Permission)
    assert all(
        Permission.ORGANIZATION_TRANSFER not in permissions
        for role, permissions in ROLE_PERMISSIONS.items()
        if role is not Role.OWNER
    )


def test_roles_follow_the_reviewed_least_privilege_boundaries():
    viewer = ROLE_PERMISSIONS[Role.VIEWER]
    auditor = ROLE_PERMISSIONS[Role.AUDITOR]
    operator = ROLE_PERMISSIONS[Role.OPERATOR]
    admin = ROLE_PERMISSIONS[Role.ADMIN]

    assert viewer == {
        Permission.DOCKYARD_READ,
        Permission.INVENTORY_READ,
        Permission.FINDING_READ,
        Permission.CORRELATION_READ,
        Permission.REPORT_READ,
    }
    assert viewer < auditor
    assert viewer < operator
    assert Permission.WORKFLOW_RUN not in auditor
    assert Permission.RAW_EVIDENCE_READ in auditor
    assert Permission.SCOPE_READ in auditor
    assert Permission.MEMBERSHIP_MANAGE not in operator
    assert admin == (auditor | operator | {Permission.MEMBERSHIP_MANAGE})
    assert admin < ROLE_PERMISSIONS[Role.OWNER]


def test_unknown_role_and_inactive_principals_fail_closed():
    assert permissions_for("new-unreviewed-role") == frozenset()
    assert permissions_for(None) == frozenset()  # type: ignore[arg-type]
    disabled_user = AuthorizationContext(1, 2, 3, Role.OWNER, user_active=False)
    disabled_membership = AuthorizationContext(1, 2, 3, Role.OWNER, membership_active=False)

    for context in (disabled_user, disabled_membership):
        assert not context.allows(Permission.DOCKYARD_READ)
        with pytest.raises(AuthorizationDenied, match="Permission denied"):
            context.require(Permission.DOCKYARD_READ)


def test_local_mode_is_explicitly_the_reserved_owner_context():
    assert (
        LOCAL_AUTHORIZATION.organization_id,
        LOCAL_AUTHORIZATION.user_id,
        LOCAL_AUTHORIZATION.membership_id,
        LOCAL_AUTHORIZATION.role,
    ) == (1, 1, 1, Role.OWNER)
    assert LOCAL_AUTHORIZATION.allows(Permission.ORGANIZATION_TRANSFER)
