from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_session
from app.schemas import DockyardCreate, DockyardRead, HealthRead, VersionRead
from app.services import create_dockyard, get_dockyard, list_dockyards

router = APIRouter(prefix="/api", tags=["RedDock Core"])


@router.get("/health", response_model=HealthRead)
def health() -> HealthRead:
    return HealthRead(status="healthy", service="reddock-core")


@router.get("/version", response_model=VersionRead)
def version() -> VersionRead:
    settings = get_settings()
    return VersionRead(name=settings.app_name, version=settings.version)


@router.get("/dockyards", response_model=list[DockyardRead])
def read_dockyards(session: Session = Depends(get_session)) -> list[DockyardRead]:
    return list_dockyards(session)


@router.post("/dockyards", response_model=DockyardRead, status_code=status.HTTP_201_CREATED)
def add_dockyard(payload: DockyardCreate, session: Session = Depends(get_session)) -> DockyardRead:
    if not payload.name.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Name is required",
        )
    return create_dockyard(session, payload)


@router.get("/dockyards/{dockyard_id}", response_model=DockyardRead)
def read_dockyard(dockyard_id: int, session: Session = Depends(get_session)) -> DockyardRead:
    dockyard = get_dockyard(session, dockyard_id)
    if dockyard is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dockyard not found")
    return dockyard
