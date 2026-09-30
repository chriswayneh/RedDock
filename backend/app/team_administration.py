"""Dormant, transaction-owned administration for the configured server team.

No router registers these operations. The local owner and public signup are
excluded; the first owner still comes only from the offline bootstrap command.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from threading import Lock

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.authorization import AuthorizationContext, AuthorizationDenied, Permission, Role
from app.config import ConfigurationError, canonical_oidc_issuer
from app.models import Membership, Organization, User
from app.security_audit import (
    SecurityAction,
    SecurityOutcome,
    append_security_event,
    list_security_events,
)
from app.session_auth import revoke_membership_sessions
from app.workflow_authorization import WorkflowExecutionPolicy, current_workflow_actor

MAX_TEAM_MEMBERS = 1_000
_TEAM_LOCK = Lock()


class TeamAdministrationRejected(ValueError):
    """A requested team change conflicts with a fixed administration invariant."""


class MemberStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class MemberSnapshot:
    id: int
    user_id: int
    subject: str
    display_name: str
    role: Role
    status: MemberStatus
    user_status: str


@dataclass(frozen=True, slots=True)
class AuditSnapshot:
    id: int
    actor_user_id: int | None
    actor_membership_id: int | None
    actor_role: str | None
    action: str
    outcome: str
    target_type: str | None
    target_id: str | None
    reason_code: str | None
    request_id: str | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class AuditPage:
    items: tuple[AuditSnapshot, ...]
    next_before_id: int | None


def _snapshot(member: Membership, user: User) -> MemberSnapshot:
    return MemberSnapshot(
        member.id,
        user.id,
        user.oidc_subject,
        user.display_name,
        Role(member.role),
        MemberStatus(member.status),
        user.status,
    )


def _text(value: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TeamAdministrationRejected("Identity fields must be bounded non-control text")
    return value


def _role(value: Role | str) -> Role:
    try:
        role = Role(value)
    except (ValueError, TypeError):
        raise TeamAdministrationRejected("Unsupported membership role") from None
    if role is Role.OWNER:
        raise TeamAdministrationRejected("Owner changes require explicit ownership transfer")
    return role


def _status(value: MemberStatus | str) -> MemberStatus:
    try:
        return MemberStatus(value)
    except (ValueError, TypeError):
        raise TeamAdministrationRejected("Unsupported membership status") from None


@contextmanager
def _administration(
    session: Session,
    policy: WorkflowExecutionPolicy,
    authorization: AuthorizationContext,
    permission: Permission = Permission.MEMBERSHIP_MANAGE,
):
    if session.in_transaction():
        raise ValueError("team administration requires a fresh session transaction")
    if (
        not isinstance(policy, WorkflowExecutionPolicy)
        or policy.mode != "server"
        or policy.organization_slug == "local"
        or authorization.organization_id == 1
        or authorization.user_id == 1
        or authorization.membership_id == 1
    ):
        raise AuthorizationDenied("Permission denied")
    try:
        if canonical_oidc_issuer(policy.issuer) != policy.issuer:
            raise AuthorizationDenied("Permission denied")
    except ConfigurationError:
        raise AuthorizationDenied("Permission denied") from None
    try:
        with _TEAM_LOCK, session.begin():
            organization = session.scalar(
                select(Organization)
                .where(
                    Organization.id == authorization.organization_id,
                    Organization.slug == policy.organization_slug,
                    Organization.id != 1,
                )
                .with_for_update()
            )
            actor = (
                current_workflow_actor(
                    session,
                    policy,
                    organization_id=authorization.organization_id,
                    user_id=authorization.user_id,
                    membership_id=authorization.membership_id,
                    permission=permission,
                )
                if organization is not None
                else None
            )
            if actor is None:
                raise AuthorizationDenied("Permission denied")
            yield actor
    except IntegrityError:
        raise TeamAdministrationRejected("Identity conflicts with retained state") from None


def _target(
    session: Session,
    actor: AuthorizationContext,
    policy: WorkflowExecutionPolicy,
    membership_id: int,
) -> tuple[Membership, User]:
    identity = session.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.id == membership_id,
            Membership.organization_id == actor.organization_id,
            Membership.id != 1,
            User.id != 1,
            User.oidc_issuer == policy.issuer,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if identity is None:
        raise TeamAdministrationRejected("Member not found")
    return identity


def _audit(session: Session, actor: AuthorizationContext, membership_id: int, reason: str) -> None:
    append_security_event(
        session,
        organization_id=actor.organization_id,
        actor=actor,
        action=SecurityAction.MEMBERSHIP_CHANGE,
        outcome=SecurityOutcome.SUCCESS,
        target_type="membership",
        target_id=str(membership_id),
        reason_code=reason,
    )


def _revoke(session: Session, actor: AuthorizationContext, membership_id: int) -> None:
    revoke_membership_sessions(session, membership_id)
    append_security_event(
        session,
        organization_id=actor.organization_id,
        actor=actor,
        action=SecurityAction.MEMBERSHIP_SESSIONS_REVOKE,
        outcome=SecurityOutcome.SUCCESS,
        target_type="membership",
        target_id=str(membership_id),
        reason_code="access_changed",
    )


def list_members(
    session: Session,
    *,
    authorization: AuthorizationContext,
    policy: WorkflowExecutionPolicy,
    limit: int = 100,
    offset: int = 0,
) -> list[MemberSnapshot]:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= 100
        or isinstance(offset, bool)
        or not isinstance(offset, int)
        or not 0 <= offset <= 1_000_000
    ):
        raise TeamAdministrationRejected("Invalid roster window")
    with _administration(session, policy, authorization) as actor:
        rows = session.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.organization_id == actor.organization_id,
                User.oidc_issuer == policy.issuer,
                Membership.id != 1,
                User.id != 1,
            )
            .order_by(Membership.id)
            .offset(offset)
            .limit(limit)
        ).all()
        return [_snapshot(member, user) for member, user in rows]


def audit_history(
    session: Session,
    *,
    authorization: AuthorizationContext,
    policy: WorkflowExecutionPolicy,
    limit: int = 100,
    before_id: int | None = None,
) -> AuditPage:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise TeamAdministrationRejected("Invalid audit window")
    with _administration(session, policy, authorization, Permission.AUDIT_READ) as actor:
        try:
            rows = list_security_events(
                session, actor.organization_id, limit=limit + 1, before_id=before_id
            )
        except ValueError:
            raise TeamAdministrationRejected("Invalid audit window") from None
        items = tuple(
            AuditSnapshot(
                row.id,
                row.actor_user_id,
                row.actor_membership_id,
                row.actor_role,
                row.action,
                row.outcome,
                row.target_type,
                row.target_id,
                row.reason_code,
                row.request_id,
                row.created_at.replace(tzinfo=UTC)
                if row.created_at.tzinfo is None
                else row.created_at.astimezone(UTC),
            )
            for row in rows[:limit]
        )
        return AuditPage(items, items[-1].id if len(rows) > limit else None)


def provision_member(
    session: Session,
    *,
    authorization: AuthorizationContext,
    policy: WorkflowExecutionPolicy,
    subject: str,
    display_name: str,
    role: Role | str,
) -> MemberSnapshot:
    subject, display_name, role = _text(subject, 255), _text(display_name, 120), _role(role)
    with _administration(session, policy, authorization) as actor:
        retained = session.scalar(
            select(func.count())
            .select_from(Membership)
            .where(
                Membership.organization_id == actor.organization_id,
            )
        )
        if retained >= MAX_TEAM_MEMBERS:
            raise TeamAdministrationRejected("The team reached its fixed membership limit")
        if (
            session.scalar(
                select(User.id).where(
                    User.oidc_issuer == policy.issuer,
                    User.oidc_subject == subject,
                )
            )
            is not None
        ):
            raise TeamAdministrationRejected("Identity is already provisioned")
        user = User(
            oidc_issuer=policy.issuer,
            oidc_subject=subject,
            display_name=display_name,
            status="active",
        )
        session.add(user)
        session.flush()
        member = Membership(
            organization_id=actor.organization_id, user_id=user.id, role=role.value, status="active"
        )
        session.add(member)
        session.flush()
        _audit(session, actor, member.id, f"provisioned_{role.value}")
        return _snapshot(member, user)


def change_member(
    session: Session,
    membership_id: int,
    *,
    authorization: AuthorizationContext,
    policy: WorkflowExecutionPolicy,
    role: Role | str,
    status: MemberStatus | str,
) -> MemberSnapshot:
    role, status = _role(role), _status(status)
    with _administration(session, policy, authorization) as actor:
        member, user = _target(session, actor, policy, membership_id)
        if member.role == Role.OWNER.value:
            raise TeamAdministrationRejected("Owner changes require explicit ownership transfer")
        if (member.role, member.status) != (role.value, status.value):
            member.role, member.status = role.value, status.value
            _revoke(session, actor, member.id)
            _audit(session, actor, member.id, f"member_{role.value}_{status.value}")
        return _snapshot(member, user)


def transfer_ownership(
    session: Session,
    membership_id: int,
    *,
    authorization: AuthorizationContext,
    policy: WorkflowExecutionPolicy,
) -> MemberSnapshot:
    with _administration(session, policy, authorization, Permission.ORGANIZATION_TRANSFER) as actor:
        owners = list(
            session.scalars(
                select(Membership.id).where(
                    Membership.organization_id == actor.organization_id,
                    Membership.role == "owner",
                )
            )
        )
        if owners != [actor.membership_id]:
            raise TeamAdministrationRejected("Organization ownership is inconsistent")
        if membership_id == actor.membership_id:
            raise TeamAdministrationRejected("Choose another active team member")
        recipient, recipient_user = _target(session, actor, policy, membership_id)
        if recipient.status != "active" or recipient_user.status != "active":
            raise TeamAdministrationRejected("Choose another active team member")
        previous, _ = _target(session, actor, policy, actor.membership_id)
        previous.role, recipient.role = Role.ADMIN.value, Role.OWNER.value
        _revoke(session, actor, previous.id)
        _revoke(session, actor, recipient.id)
        _audit(session, actor, previous.id, "ownership_relinquished")
        _audit(session, actor, recipient.id, "ownership_received")
        return _snapshot(recipient, recipient_user)
