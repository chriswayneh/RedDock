import re
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authorization import AuthorizationContext
from app.models import SecurityAuditEvent

_BOUNDED_IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}")


class SecurityAction(StrEnum):
    DOCKYARD_CREATE = "dockyard.create"
    SCOPE_ADD = "scope.add"
    SCOPE_REMOVE = "scope.remove"
    SCOPE_EVALUATE = "scope.evaluate"
    FINDING_UPDATE = "finding.update"
    REPORT_EXPORT = "report.export"
    DETECTION_REQUEST = "detection.request"
    DETECTION_PUBLISH = "detection.publish"
    CORRELATION_REQUEST = "correlation.request"
    CORRELATION_PUBLISH = "correlation.publish"
    REPORT_REQUEST = "report.request"
    REPORT_PUBLISH = "report.publish"
    LAB_AUTHORIZE = "lab.authorize"
    LAB_REVOKE = "lab.revoke"
    VALIDATION_REQUEST = "validation.request"
    VALIDATION_APPROVE = "validation.approve"
    INTELLIGENCE_REQUEST = "intelligence.request"
    INTELLIGENCE_APPROVE = "intelligence.approve"
    DISCOVERY_REQUEST = "discovery.request"
    DISCOVERY_EXECUTE = "discovery.execute"
    SESSION_ISSUE = "session.issue"
    SESSION_ROTATE = "session.rotate"
    SESSION_REPLAY = "session.replay"
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
    before_id: int | None = None,
) -> list[SecurityAuditEvent]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
        raise ValueError("Audit event limit must be between 1 and 1000")
    if before_id is not None and (
        isinstance(before_id, bool) or not isinstance(before_id, int)
        or not 1 <= before_id <= 9_223_372_036_854_775_807
    ):
        raise ValueError("Audit cursor must be a positive database identifier")
    statement = select(SecurityAuditEvent).where(
        SecurityAuditEvent.organization_id == organization_id,
    )
    if before_id is not None:
        statement = statement.where(SecurityAuditEvent.id < before_id)
    return list(
        session.scalars(
            statement.order_by(SecurityAuditEvent.id.desc())
            .limit(limit)
        )
    )
