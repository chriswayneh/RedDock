"""Current workflow authority and durable attribution for queued discovery."""

from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authorization import AuthorizationContext, AuthorizationDenied, Permission, Role
from app.config import DormantServerRuntimeConfig
from app.models import Dockyard, Membership, Organization, SecurityAuditEvent, User
from app.security_audit import SecurityAction, SecurityOutcome


@dataclass(frozen=True, slots=True)
class WorkflowExecutionPolicy:
    mode: Literal["local", "server"]
    issuer: str
    organization_slug: str


LOCAL_WORKFLOW_POLICY = WorkflowExecutionPolicy("local", "urn:reddock:local", "local")


def workflow_execution_policy(
    config: DormantServerRuntimeConfig | None,
) -> WorkflowExecutionPolicy:
    if config is None:
        return LOCAL_WORKFLOW_POLICY
    if not isinstance(config, DormantServerRuntimeConfig):
        raise ValueError("validated workflow configuration is required")
    return WorkflowExecutionPolicy("server", config.oidc_issuer, config.organization_slug)


def current_workflow_actor(
    session: Session, policy: WorkflowExecutionPolicy, *,
    organization_id: int, user_id: int | None, membership_id: int | None,
    permission: Permission = Permission.WORKFLOW_RUN,
) -> AuthorizationContext | None:
    """Lock and re-read identity; never reuse a queued role or browser credential."""

    if not isinstance(policy, WorkflowExecutionPolicy) or policy.mode not in {"local", "server"}:
        return None
    if user_id is None or membership_id is None:
        return None
    if policy.mode == "local" and (
        policy != LOCAL_WORKFLOW_POLICY or (organization_id, user_id, membership_id) != (1, 1, 1)
    ):
        return None
    identity = session.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(
            Membership.id == membership_id, Membership.user_id == user_id,
            Membership.organization_id == organization_id,
            Organization.slug == policy.organization_slug,
            User.oidc_issuer == policy.issuer,
        )
        .with_for_update(of=(Membership, User))
        .execution_options(populate_existing=True)
    ).one_or_none()
    if identity is None:
        return None
    membership, user = identity
    try:
        actor = AuthorizationContext(
            organization_id=organization_id, user_id=user_id, membership_id=membership_id,
            role=Role(membership.role), user_active=user.status == "active",
            membership_active=membership.status == "active",
        )
    except ValueError:
        return None
    return actor if actor.allows(permission) else None


def require_workflow_actor(
    session: Session, policy: WorkflowExecutionPolicy, authorization: AuthorizationContext,
    dockyard_id: int, permission: Permission, *, lock_workspace: bool = False,
) -> AuthorizationContext:
    """Require current authority within the exact workspace organization."""
    statement = select(Dockyard.organization_id).where(
        Dockyard.id == dockyard_id, Dockyard.organization_id == authorization.organization_id,
    )
    if lock_workspace:
        statement = statement.with_for_update()
    organization_id = session.scalar(statement)
    actor = current_workflow_actor(
        session, policy, organization_id=authorization.organization_id,
        user_id=authorization.user_id, membership_id=authorization.membership_id,
        permission=permission,
    ) if organization_id is not None else None
    if actor is None:
        raise AuthorizationDenied("Permission denied")
    return actor


def discovery_execution_actor(
    session: Session, policy: WorkflowExecutionPolicy, *,
    request_event_id: int, run_id: int, organization_id: int,
) -> AuthorizationContext | None:
    """Resolve one committed admission receipt, scoped to its exact run and tenant."""

    event = session.scalar(select(SecurityAuditEvent).where(
        SecurityAuditEvent.id == request_event_id,
        SecurityAuditEvent.organization_id == organization_id,
        SecurityAuditEvent.action == SecurityAction.DISCOVERY_REQUEST.value,
        SecurityAuditEvent.outcome == SecurityOutcome.SUCCESS.value,
        SecurityAuditEvent.target_type == "discovery_run",
        SecurityAuditEvent.target_id == str(run_id),
    ).execution_options(populate_existing=True))
    if event is None:
        return None
    return current_workflow_actor(
        session, policy, organization_id=organization_id,
        user_id=event.actor_user_id, membership_id=event.actor_membership_id,
    )
