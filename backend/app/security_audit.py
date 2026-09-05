import re
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authorization import AuthorizationContext
from app.models import SecurityAuditEvent

_BOUNDED_IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}")


class SecurityAction(StrEnum):
    SESSION_ISSUE = "session.issue"
    SESSION_REVOKE = "session.revoke"
    MEMBERSHIP_SESSIONS_REVOKE = "membership.sessions_revoke"
    AUTHENTICATION_DENY = "authentication.deny"
    MEMBERSHIP_CHANGE = "membership.change"


class SecurityOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


def _optional_identifier(value: str | None, field: str) -> str | None:
    if value is not None and not _BOUNDED_IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a bounded opaque identifier")
    return value


def append_security_event(
    session: Session,
    *,
    organization_id: int,
    action: SecurityAction,
    outcome: SecurityOutcome,
    actor: AuthorizationContext | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    reason_code: str | None = None,
    request_id: str | None = None,
) -> SecurityAuditEvent:
    """Append a structured event without accepting free-form or secret-bearing detail."""
    if actor is not None and actor.organization_id != organization_id:
        raise ValueError("Audit actor must belong to the event organization")
    event = SecurityAuditEvent(
        organization_id=organization_id,
        actor_user_id=actor.user_id if actor is not None else None,
        actor_membership_id=actor.membership_id if actor is not None else None,
        actor_role=actor.role.value if actor is not None else None,
        action=action.value,
        outcome=outcome.value,
        target_type=_optional_identifier(target_type, "target_type"),
        target_id=_optional_identifier(target_id, "target_id"),
        reason_code=_optional_identifier(reason_code, "reason_code"),
        request_id=_optional_identifier(request_id, "request_id"),
    )
    session.add(event)
    session.flush()
    return event


def list_security_events(
    session: Session,
    organization_id: int,
    *,
    limit: int = 100,
) -> list[SecurityAuditEvent]:
    if not 1 <= limit <= 1_000:
        raise ValueError("Audit event limit must be between 1 and 1000")
    return list(
        session.scalars(
            select(SecurityAuditEvent)
            .where(SecurityAuditEvent.organization_id == organization_id)
            .order_by(SecurityAuditEvent.id.desc())
            .limit(limit)
        )
    )
