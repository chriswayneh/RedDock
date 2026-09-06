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
    INTELLIGENCE_READ = "intelligence:read"
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
    Permission.INTELLIGENCE_READ,
    Permission.REPORT_EXPORT,
    Permission.AUDIT_READ,
}
_OPERATOR = _VIEWER | {
    Permission.DOCKYARD_MANAGE,
    Permission.SCOPE_MANAGE,
    Permission.SCOPE_READ,
    Permission.RAW_EVIDENCE_READ,
    Permission.INTELLIGENCE_READ,
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

# This manifest is deliberately separate from enforcement while server mode is
# unavailable. Its completeness test prevents a route from reaching that mode
# without an explicit public/protected decision and reviewed permission.
PUBLIC_ROUTES: Final = frozenset(
    {
        ("GET", "/api/health"),
        ("GET", "/api/ready"),
        ("GET", "/api/version"),
    }
)
ROUTE_PERMISSIONS: Final = MappingProxyType(
    {
        ("GET", "/api/detectors"): Permission.DOCKYARD_READ,
        ("GET", "/api/adapters"): Permission.DOCKYARD_READ,
        ("GET", "/api/lab/status"): Permission.DOCKYARD_READ,
        ("GET", "/api/dockyards"): Permission.DOCKYARD_READ,
        ("POST", "/api/dockyards"): Permission.DOCKYARD_MANAGE,
        ("GET", "/api/dockyards/{dockyard_id}"): Permission.DOCKYARD_READ,
        ("GET", "/api/dockyards/{dockyard_id}/lab/authorizations"): Permission.AUDIT_READ,
        ("POST", "/api/dockyards/{dockyard_id}/lab/authorizations"): Permission.LAB_AUTHORIZE,
        (
            "POST",
            "/api/dockyards/{dockyard_id}/lab/authorizations/{authorization_id}/revoke",
        ): Permission.LAB_AUTHORIZE,
        ("GET", "/api/dockyards/{dockyard_id}/lab/audit"): Permission.AUDIT_READ,
        ("GET", "/api/dockyards/{dockyard_id}/scope"): Permission.SCOPE_READ,
        ("POST", "/api/dockyards/{dockyard_id}/scope"): Permission.SCOPE_MANAGE,
        ("DELETE", "/api/dockyards/{dockyard_id}/scope/{entry_id}"): Permission.SCOPE_MANAGE,
        ("POST", "/api/dockyards/{dockyard_id}/scope/evaluate"): Permission.SCOPE_MANAGE,
        ("GET", "/api/dockyards/{dockyard_id}/assets"): Permission.INVENTORY_READ,
        ("GET", "/api/dockyards/{dockyard_id}/assets/{asset_id}"): Permission.INVENTORY_READ,
        ("GET", "/api/dockyards/{dockyard_id}/services"): Permission.INVENTORY_READ,
        ("GET", "/api/dockyards/{dockyard_id}/observations"): Permission.INVENTORY_READ,
        ("GET", "/api/dockyards/{dockyard_id}/discoveries"): Permission.INVENTORY_READ,
        ("POST", "/api/dockyards/{dockyard_id}/discoveries"): Permission.WORKFLOW_RUN,
        ("GET", "/api/dockyards/{dockyard_id}/discoveries/{run_id}"): Permission.INVENTORY_READ,
        ("GET", "/api/dockyards/{dockyard_id}/evidence"): Permission.RAW_EVIDENCE_READ,
        ("GET", "/api/dockyards/{dockyard_id}/detections"): Permission.FINDING_READ,
        ("POST", "/api/dockyards/{dockyard_id}/detections"): Permission.WORKFLOW_RUN,
        ("GET", "/api/dockyards/{dockyard_id}/detections/{run_id}"): Permission.FINDING_READ,
        ("GET", "/api/dockyards/{dockyard_id}/correlations"): Permission.CORRELATION_READ,
        ("POST", "/api/dockyards/{dockyard_id}/correlations"): Permission.WORKFLOW_RUN,
        ("GET", "/api/dockyards/{dockyard_id}/redpath"): Permission.CORRELATION_READ,
        ("GET", "/api/intelligence/provider"): Permission.INTELLIGENCE_READ,
        ("GET", "/api/dockyards/{dockyard_id}/intelligence"): Permission.INTELLIGENCE_READ,
        ("POST", "/api/dockyards/{dockyard_id}/intelligence"): Permission.WORKFLOW_RUN,
        (
            "POST",
            "/api/dockyards/{dockyard_id}/intelligence/{run_id}/approve",
        ): Permission.INTELLIGENCE_APPROVE,
        ("GET", "/api/dockyards/{dockyard_id}/reports"): Permission.REPORT_READ,
        ("POST", "/api/dockyards/{dockyard_id}/reports"): Permission.WORKFLOW_RUN,
        ("GET", "/api/dockyards/{dockyard_id}/reports/{run_id}"): Permission.REPORT_READ,
        (
            "GET",
            "/api/dockyards/{dockyard_id}/reports/{run_id}/technical",
        ): Permission.REPORT_EXPORT,
        (
            "GET",
            "/api/dockyards/{dockyard_id}/reports/{run_id}/executive",
        ): Permission.REPORT_EXPORT,
        (
            "GET",
            "/api/dockyards/{dockyard_id}/reports/{run_id}/manifest",
        ): Permission.REPORT_EXPORT,
        (
            "GET",
            "/api/dockyards/{dockyard_id}/reports/{run_id}/dockpack",
        ): Permission.REPORT_EXPORT,
        ("GET", "/api/dockyards/{dockyard_id}/validations"): Permission.FINDING_READ,
        (
            "POST",
            "/api/dockyards/{dockyard_id}/findings/{finding_id}/validations",
        ): Permission.WORKFLOW_RUN,
        ("GET", "/api/dockyards/{dockyard_id}/validations/{run_id}"): Permission.FINDING_READ,
        (
            "POST",
            "/api/dockyards/{dockyard_id}/validations/{run_id}/approve",
        ): Permission.WORKFLOW_RUN,
        ("GET", "/api/dockyards/{dockyard_id}/findings"): Permission.FINDING_READ,
        ("GET", "/api/dockyards/{dockyard_id}/findings/{finding_id}"): Permission.FINDING_READ,
        ("PATCH", "/api/dockyards/{dockyard_id}/findings/{finding_id}"): Permission.FINDING_UPDATE,
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
