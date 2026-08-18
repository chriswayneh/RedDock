from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dockguard import ScopeRejected, ScopeRule, ScopeRuleType, normalize_scope_value
from app.models import Dockyard, ScopeEntry
from app.schemas import DockyardCreate, ScopeEntryCreate


def list_dockyards(session: Session) -> list[Dockyard]:
    statement = select(Dockyard).order_by(Dockyard.updated_at.desc(), Dockyard.id.desc())
    return list(session.scalars(statement))


def create_dockyard(session: Session, payload: DockyardCreate) -> Dockyard:
    dockyard = Dockyard(name=payload.name.strip(), description=payload.description)
    session.add(dockyard)
    session.commit()
    session.refresh(dockyard)
    return dockyard


def get_dockyard(session: Session, dockyard_id: int) -> Dockyard | None:
    return session.get(Dockyard, dockyard_id)


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


def add_scope_entry(session: Session, dockyard_id: int, payload: ScopeEntryCreate) -> ScopeEntry:
    """Store one normalized scope entry, rejecting broad or duplicate values."""
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
    session.commit()
    session.refresh(entry)
    return entry


def remove_scope_entry(session: Session, dockyard_id: int, entry_id: int) -> bool:
    entry = session.scalar(
        select(ScopeEntry).where(ScopeEntry.dockyard_id == dockyard_id, ScopeEntry.id == entry_id)
    )
    if entry is None:
        return False
    session.delete(entry)
    session.commit()
    return True
