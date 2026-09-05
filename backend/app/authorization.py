from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class Permission(StrEnum):
    DOCKYARD_READ = "dockyard:read"
    DOCKYARD_MANAGE = "dockyard:manage"
    SCOPE_READ = "scope:read"
    SCOPE_MANAGE = "scope:manage"
    INVENTORY_READ = "inventory:read"
    FINDING_READ = "finding:read"
    CORRELATION_READ = "correlation:read"
    REPORT_READ = "report:read"
    RAW_EVIDENCE_READ = "evidence:read_raw"
    WORKFLOW_RUN = "workflow:run"
    FINDING_UPDATE = "finding:update"
    INTELLIGENCE_APPROVE = "intelligence:approve"
    LAB_AUTHORIZE = "lab:authorize"
    REPORT_EXPORT = "report:export"
    AUDIT_READ = "audit:read"
    MEMBERSHIP_MANAGE = "membership:manage"
    ORGANIZATION_TRANSFER = "organization:transfer"


_VIEWER = frozenset(
    {
        Permission.DOCKYARD_READ,
        Permission.INVENTORY_READ,
        Permission.FINDING_READ,
        Permission.CORRELATION_READ,
        Permission.REPORT_READ,
    }
)
_AUDITOR = _VIEWER | {
    Permission.RAW_EVIDENCE_READ,
    Permission.SCOPE_READ,
    Permission.REPORT_EXPORT,
    Permission.AUDIT_READ,
}
_OPERATOR = _VIEWER | {
    Permission.DOCKYARD_MANAGE,
    Permission.SCOPE_MANAGE,
    Permission.SCOPE_READ,
    Permission.RAW_EVIDENCE_READ,
    Permission.WORKFLOW_RUN,
    Permission.FINDING_UPDATE,
    Permission.INTELLIGENCE_APPROVE,
    Permission.LAB_AUTHORIZE,
    Permission.REPORT_EXPORT,
}
_ADMIN = _OPERATOR | _AUDITOR | {Permission.MEMBERSHIP_MANAGE}
_OWNER = frozenset(Permission)

ROLE_PERMISSIONS: Final = MappingProxyType(
    {
        Role.OWNER: _OWNER,
        Role.ADMIN: frozenset(_ADMIN),
        Role.OPERATOR: frozenset(_OPERATOR),
        Role.AUDITOR: frozenset(_AUDITOR),
        Role.VIEWER: _VIEWER,
    }
)


class AuthorizationDenied(RuntimeError):
    """The principal is inactive, the role is unknown, or permission is absent."""


def permissions_for(role: Role | str) -> frozenset[Permission]:
    """Return no permissions for an unknown stored role instead of guessing."""
    try:
        parsed = Role(role)
    except (TypeError, ValueError):
        return frozenset()
    return ROLE_PERMISSIONS[parsed]


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    organization_id: int
    user_id: int
    membership_id: int
    role: Role
    user_active: bool = True
    membership_active: bool = True

    def allows(self, permission: Permission) -> bool:
        return (
            self.user_active
            and self.membership_active
            and permission in permissions_for(self.role)
        )

    def require(self, permission: Permission) -> None:
        if not self.allows(permission):
            raise AuthorizationDenied("Permission denied")


LOCAL_AUTHORIZATION: Final = AuthorizationContext(
    organization_id=1,
    user_id=1,
    membership_id=1,
    role=Role.OWNER,
)
