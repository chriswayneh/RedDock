from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Dockyard
from app.schemas import DockyardCreate


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
