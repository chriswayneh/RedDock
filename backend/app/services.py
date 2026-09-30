from threading import Lock

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authorization import AuthorizationContext, AuthorizationDenied, Permission
from app.config import get_settings
from app.dockguard import ScopeRejected, ScopeRule, ScopeRuleType, normalize_scope_value
from app.models import Dockyard, ScopeEntry
from app.schemas import DockyardCreate, ScopeEntryCreate
from app.security_audit import SecurityAction, SecurityOutcome, append_security_event
from app.workflow_authorization import (
    WorkflowExecutionPolicy,
    current_workflow_actor,
    require_workflow_actor,
)

_SCOPE_MUTATION_LOCK = Lock()


def list_dockyards(session: Session, organization_id: int) -> list[Dockyard]:
    statement = (
        select(Dockyard)
        .where(Dockyard.organization_id == organization_id)
        .order_by(Dockyard.updated_at.desc(), Dockyard.id.desc())
    )
    return list(session.scalars(statement))


def create_dockyard(
    session: Session, organization_id: int, payload: DockyardCreate, *,
    authorization: AuthorizationContext, policy: WorkflowExecutionPolicy,
) -> Dockyard:
    actor = current_workflow_actor(
        session, policy, organization_id=organization_id,
        user_id=authorization.user_id, membership_id=authorization.membership_id,
        permission=Permission.DOCKYARD_MANAGE,
    ) if authorization.organization_id == organization_id else None
    if actor is None:
        raise AuthorizationDenied("Permission denied")
    dockyard = Dockyard(
        organization_id=organization_id,
        name=payload.name.strip(),
        description=payload.description,
    )
    session.add(dockyard)
    session.flush()
    append_security_event(
        session, organization_id=actor.organization_id, actor=actor,
        action=SecurityAction.DOCKYARD_CREATE, outcome=SecurityOutcome.SUCCESS,
        target_type="dockyard", target_id=str(dockyard.id), reason_code="dockyard_created",
    )
    session.commit()
    session.refresh(dockyard)
    return dockyard


def get_dockyard(session: Session, organization_id: int, dockyard_id: int) -> Dockyard | None:
    return session.scalar(
        select(Dockyard).where(
            Dockyard.organization_id == organization_id,
            Dockyard.id == dockyard_id,
        )
    )


def list_scope_entries(session: Session, dockyard_id: int) -> list[ScopeEntry]:
    statement = (
        select(ScopeEntry)
        .where(ScopeEntry.dockyard_id == dockyard_id)
        .order_by(ScopeEntry.rule, ScopeEntry.value)
    )
    return list(session.scalars(statement))


def scope_rules(session: Session, dockyard_id: int) -> list[ScopeRule]:
    """The Dockyard scope in the form DockGuard evaluates."""
    return [
        ScopeRule(rule=ScopeRuleType(entry.rule), value=entry.value)
        for entry in list_scope_entries(session, dockyard_id)
    ]


def add_scope_entry(
    session: Session, dockyard_id: int, payload: ScopeEntryCreate, *,
    authorization: AuthorizationContext, policy: WorkflowExecutionPolicy,
) -> ScopeEntry:
    with _SCOPE_MUTATION_LOCK:
        return _add_scope_entry(
            session, dockyard_id, payload, authorization=authorization, policy=policy,
        )


def _add_scope_entry(
    session: Session, dockyard_id: int, payload: ScopeEntryCreate, *,
    authorization: AuthorizationContext, policy: WorkflowExecutionPolicy,
) -> ScopeEntry:
    """Store one normalized scope entry, rejecting broad or duplicate values."""
    actor = require_workflow_actor(
        session, policy, authorization, dockyard_id, Permission.SCOPE_MANAGE, lock_workspace=True,
    )
    target = normalize_scope_value(payload.target)
    existing = list_scope_entries(session, dockyard_id)
    if len(existing) >= get_settings().max_scope_entries:
        raise ScopeRejected(
            f"A Dockyard may hold at most {get_settings().max_scope_entries} scope entries"
        )
    if any(entry.rule == payload.rule and entry.value == target.value for entry in existing):
        raise ScopeRejected(f"{target.value} is already a {payload.rule} entry")

    entry = ScopeEntry(
        dockyard_id=dockyard_id,
        rule=str(payload.rule),
        kind=str(target.kind),
        value=target.value,
        note=payload.note,
    )
    session.add(entry)
    session.flush()
    append_security_event(
        session, organization_id=actor.organization_id, actor=actor,
        action=SecurityAction.SCOPE_ADD, outcome=SecurityOutcome.SUCCESS,
        target_type="scope_entry", target_id=str(entry.id), reason_code="scope_added",
    )
    session.commit()
    session.refresh(entry)
    return entry


def remove_scope_entry(
    session: Session, dockyard_id: int, entry_id: int, *,
    authorization: AuthorizationContext, policy: WorkflowExecutionPolicy,
) -> bool:
    with _SCOPE_MUTATION_LOCK:
        return _remove_scope_entry(
            session, dockyard_id, entry_id, authorization=authorization, policy=policy,
        )


def _remove_scope_entry(
    session: Session, dockyard_id: int, entry_id: int, *,
    authorization: AuthorizationContext, policy: WorkflowExecutionPolicy,
) -> bool:
    actor = require_workflow_actor(
        session, policy, authorization, dockyard_id, Permission.SCOPE_MANAGE, lock_workspace=True,
    )
    entry = session.scalar(
        select(ScopeEntry).where(ScopeEntry.dockyard_id == dockyard_id, ScopeEntry.id == entry_id)
    )
    if entry is None:
        return False
    session.delete(entry)
    append_security_event(
        session, organization_id=actor.organization_id, actor=actor,
        action=SecurityAction.SCOPE_REMOVE, outcome=SecurityOutcome.SUCCESS,
        target_type="scope_entry", target_id=str(entry_id), reason_code="scope_removed",
    )
    session.commit()
    return True
