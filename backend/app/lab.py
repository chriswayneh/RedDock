"""Phase 7's independent, auditable lab-capability policy gate.

Lab mode is never inferred from scope. A deployment owner must opt the process
in, and an operator must separately create a short-lived authorization for one
fixed capability in one Dockyard. Every policy check is retained, including a
denial and the second check immediately before execution.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.lab_capabilities import LAB_ACKNOWLEDGEMENT, capability
from app.models import LabAuditEvent, LabAuthorization


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str
    authorization_id: int | None = None


def create_authorization(
    session: Session,
    dockyard_id: int,
    capability_id: str,
    acknowledgement: str,
    note: str,
    duration_minutes: int,
) -> tuple[LabAuthorization, PolicyDecision]:
    """Persist an authorization decision; deployment-disabled attempts are audited."""
    settings = get_settings()
    now = datetime.now(UTC)
    if capability(capability_id) is None:
        raise ValueError("Unknown lab capability")
    if acknowledgement != LAB_ACKNOWLEDGEMENT:
        raise ValueError("The exact lab acknowledgement is required")
    if not 5 <= duration_minutes <= settings.max_lab_authorization_minutes:
        raise ValueError(
            f"Lab authorization must last 5–{settings.max_lab_authorization_minutes} minutes"
        )
    if _authorization_count(session, dockyard_id) >= settings.max_lab_authorizations_per_dockyard:
        raise ValueError("This Dockyard has reached its lab-authorization history limit")

    enabled = settings.lab_mode_enabled
    reason = (
        f"Authorized for {duration_minutes} minutes by explicit Dockyard acknowledgement"
        if enabled
        else "Lab mode is disabled by the deployment owner"
    )
    if enabled:
        _supersede_active_authorizations(session, dockyard_id, capability_id, now)
    authorization = LabAuthorization(
        dockyard_id=dockyard_id,
        capability=capability_id,
        status="active" if enabled else "denied",
        acknowledgement=acknowledgement,
        note=note,
        expires_at=now + timedelta(minutes=duration_minutes) if enabled else now,
    )
    session.add(authorization)
    session.flush()
    _record(
        session,
        dockyard_id=dockyard_id,
        capability_id=capability_id,
        action="authorize",
        decision="allowed" if enabled else "denied",
        reason=reason,
        authorization_id=authorization.id,
    )
    session.commit()
    session.refresh(authorization)
    return authorization, PolicyDecision(enabled, reason, authorization.id if enabled else None)


def check_capability(
    session: Session,
    dockyard_id: int,
    capability_id: str,
    *,
    action: str,
    discovery_run_id: int | None = None,
) -> PolicyDecision:
    """Evaluate both lab gates and append the decision to the audit trail."""
    settings = get_settings()
    if capability(capability_id) is None:
        decision = PolicyDecision(False, "The requested lab capability is not registered")
    elif not settings.lab_mode_enabled:
        decision = PolicyDecision(False, "Lab mode is disabled by the deployment owner")
    else:
        authorization = _active_authorization(session, dockyard_id, capability_id)
        if authorization is None:
            decision = PolicyDecision(
                False,
                "No active, unexpired Dockyard authorization exists for this lab capability",
            )
        else:
            decision = PolicyDecision(
                True,
                f"Allowed by lab authorization {authorization.id}",
                authorization.id,
            )
    _record(
        session,
        dockyard_id=dockyard_id,
        capability_id=capability_id,
        action=action,
        decision="allowed" if decision.allowed else "denied",
        reason=decision.reason,
        authorization_id=decision.authorization_id,
        discovery_run_id=discovery_run_id,
    )
    return decision


def record_denial(
    session: Session,
    dockyard_id: int,
    capability_id: str,
    *,
    action: str,
    reason: str,
    discovery_run_id: int | None = None,
) -> PolicyDecision:
    """Retain a denial imposed before the ordinary capability check can run."""
    decision = PolicyDecision(False, reason)
    _record(
        session,
        dockyard_id=dockyard_id,
        capability_id=capability_id,
        action=action,
        decision="denied",
        reason=reason,
        discovery_run_id=discovery_run_id,
    )
    return decision


def revoke_authorization(
    session: Session, dockyard_id: int, authorization_id: int
) -> LabAuthorization | None:
    authorization = session.scalar(
        select(LabAuthorization).where(
            LabAuthorization.id == authorization_id,
            LabAuthorization.dockyard_id == dockyard_id,
        )
    )
    if authorization is None:
        return None
    if authorization.status == "active":
        authorization.status = "revoked"
        authorization.revoked_at = datetime.now(UTC)
    _record(
        session,
        dockyard_id=dockyard_id,
        capability_id=authorization.capability,
        action="revoke",
        decision="allowed",
        reason=f"Lab authorization {authorization.id} revoked",
        authorization_id=authorization.id,
    )
    session.commit()
    session.refresh(authorization)
    return authorization


def list_authorizations(session: Session, dockyard_id: int, limit: int) -> list[dict]:
    statement = (
        select(LabAuthorization)
        .where(LabAuthorization.dockyard_id == dockyard_id)
        .order_by(LabAuthorization.id.desc())
        .limit(limit)
    )
    return [_authorization_document(item) for item in session.scalars(statement)]


def list_audit_events(session: Session, dockyard_id: int, limit: int) -> list[LabAuditEvent]:
    statement = (
        select(LabAuditEvent)
        .where(LabAuditEvent.dockyard_id == dockyard_id)
        .order_by(LabAuditEvent.id.desc())
        .limit(limit)
    )
    return list(session.scalars(statement))


def _authorization_document(authorization: LabAuthorization) -> dict:
    status = authorization.status
    if status == "active" and _as_utc(authorization.expires_at) <= datetime.now(UTC):
        status = "expired"
    return {
        "id": authorization.id,
        "dockyard_id": authorization.dockyard_id,
        "capability": authorization.capability,
        "status": status,
        "acknowledgement": authorization.acknowledgement,
        "note": authorization.note,
        "created_at": authorization.created_at,
        "expires_at": authorization.expires_at,
        "revoked_at": authorization.revoked_at,
    }


def _active_authorization(
    session: Session, dockyard_id: int, capability_id: str
) -> LabAuthorization | None:
    now = datetime.now(UTC)
    candidates = session.scalars(
        select(LabAuthorization)
        .where(
            LabAuthorization.dockyard_id == dockyard_id,
            LabAuthorization.capability == capability_id,
            LabAuthorization.status == "active",
        )
        .order_by(LabAuthorization.id.desc())
        .limit(20)
    )
    return next(
        (candidate for candidate in candidates if _as_utc(candidate.expires_at) > now), None
    )


def _authorization_count(session: Session, dockyard_id: int) -> int:
    return session.scalar(
        select(func.count())
        .select_from(LabAuthorization)
        .where(LabAuthorization.dockyard_id == dockyard_id)
    ) or 0


def _supersede_active_authorizations(
    session: Session, dockyard_id: int, capability_id: str, now: datetime
) -> None:
    active = session.scalars(
        select(LabAuthorization).where(
            LabAuthorization.dockyard_id == dockyard_id,
            LabAuthorization.capability == capability_id,
            LabAuthorization.status == "active",
        )
    )
    for authorization in active:
        authorization.status = "superseded"
        authorization.revoked_at = now


def _record(
    session: Session,
    *,
    dockyard_id: int,
    capability_id: str,
    action: str,
    decision: str,
    reason: str,
    authorization_id: int | None = None,
    discovery_run_id: int | None = None,
) -> None:
    session.add(
        LabAuditEvent(
            dockyard_id=dockyard_id,
            capability=capability_id,
            action=action,
            decision=decision,
            reason=reason[:500],
            authorization_id=authorization_id,
            discovery_run_id=discovery_run_id,
        )
    )


def _as_utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
