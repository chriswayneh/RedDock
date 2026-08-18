from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_session
from app.discovery import registry
from app.discovery import runner as discovery_runner
from app.dockguard import Evaluation, ScopeRejected, evaluate, system_resolver
from app.inventory import get_asset, list_assets, list_observations, list_services
from app.models import Dockyard, EvidenceRecord
from app.schemas import (
    AdapterRead,
    AssetDetailRead,
    AssetRead,
    DiscoveryCreate,
    DiscoveryRunRead,
    DockyardCreate,
    DockyardRead,
    EvidenceRecordRead,
    HealthRead,
    ObservationRead,
    ProfileRead,
    ScopeEntryCreate,
    ScopeEntryRead,
    ScopeEvaluateRequest,
    ScopeEvaluationRead,
    ServiceRead,
    ServiceRowRead,
    VersionRead,
)
from app.services import (
    add_scope_entry,
    create_dockyard,
    get_dockyard,
    list_dockyards,
    list_scope_entries,
    remove_scope_entry,
    scope_rules,
)
from app.targets import TargetError

router = APIRouter(prefix="/api", tags=["RedDock Core"])

ListLimit = Query(default=100, ge=1, le=500)


def require_dockyard(dockyard_id: int, session: Session) -> Dockyard:
    dockyard = get_dockyard(session, dockyard_id)
    if dockyard is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dockyard not found")
    return dockyard


def _evaluation_body(evaluation: Evaluation) -> ScopeEvaluationRead:
    return ScopeEvaluationRead(
        decision=str(evaluation.decision),
        target=evaluation.target,
        reason=evaluation.reason,
        normalized_target=evaluation.normalized_target,
        target_kind=evaluation.target_kind,
        matched_rule=evaluation.matched_rule,
        resolved_addresses=list(evaluation.resolved_addresses),
        excluded_addresses=list(evaluation.excluded_addresses),
        allowed=evaluation.allowed,
    )


@router.get("/health", response_model=HealthRead)
def health() -> HealthRead:
    return HealthRead(status="healthy", service="reddock-core")


@router.get("/version", response_model=VersionRead)
def version() -> VersionRead:
    settings = get_settings()
    return VersionRead(name=settings.app_name, version=settings.version, phase=settings.phase)


@router.get("/adapters", response_model=list[AdapterRead])
def read_adapters() -> list[AdapterRead]:
    return [
        AdapterRead(
            name=adapter.name,
            version=adapter.version,
            title=adapter.title,
            description=adapter.description,
            profiles=[ProfileRead(**asdict(profile)) for profile in adapter.profiles],
            target_kinds=[str(kind) for kind in adapter.supported_kinds],
        )
        for adapter in registry.available_adapters()
    ]


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
    return require_dockyard(dockyard_id, session)


@router.get("/dockyards/{dockyard_id}/scope", response_model=list[ScopeEntryRead])
def read_scope(dockyard_id: int, session: Session = Depends(get_session)) -> list[ScopeEntryRead]:
    require_dockyard(dockyard_id, session)
    return list_scope_entries(session, dockyard_id)


@router.post(
    "/dockyards/{dockyard_id}/scope",
    response_model=ScopeEntryRead,
    status_code=status.HTTP_201_CREATED,
)
def add_scope(
    dockyard_id: int,
    payload: ScopeEntryCreate,
    session: Session = Depends(get_session),
) -> ScopeEntryRead:
    require_dockyard(dockyard_id, session)
    try:
        return add_scope_entry(session, dockyard_id, payload)
    except (TargetError, ScopeRejected) as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)
        ) from error


@router.delete("/dockyards/{dockyard_id}/scope/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scope(
    dockyard_id: int, entry_id: int, session: Session = Depends(get_session)
) -> Response:
    require_dockyard(dockyard_id, session)
    if not remove_scope_entry(session, dockyard_id, entry_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope entry not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/dockyards/{dockyard_id}/scope/evaluate", response_model=ScopeEvaluationRead)
def evaluate_scope(
    dockyard_id: int,
    payload: ScopeEvaluateRequest,
    session: Session = Depends(get_session),
) -> ScopeEvaluationRead:
    require_dockyard(dockyard_id, session)
    evaluation = evaluate(
        payload.target,
        scope_rules(session, dockyard_id),
        resolver=system_resolver if payload.resolve else None,
    )
    return _evaluation_body(evaluation)


@router.get("/dockyards/{dockyard_id}/assets", response_model=list[AssetRead])
def read_assets(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[AssetRead]:
    require_dockyard(dockyard_id, session)
    return [
        AssetRead.model_validate(asset).model_copy(update={"service_count": count})
        for asset, count in list_assets(session, dockyard_id, limit)
    ]


@router.get("/dockyards/{dockyard_id}/assets/{asset_id}", response_model=AssetDetailRead)
def read_asset(
    dockyard_id: int, asset_id: int, session: Session = Depends(get_session)
) -> AssetDetailRead:
    require_dockyard(dockyard_id, session)
    asset = get_asset(session, dockyard_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    detail = AssetDetailRead.model_validate(asset)
    return detail.model_copy(update={"service_count": len(asset.services)})


@router.get("/dockyards/{dockyard_id}/services", response_model=list[ServiceRowRead])
def read_services(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[ServiceRowRead]:
    require_dockyard(dockyard_id, session)
    return [
        ServiceRowRead(
            **ServiceRead.model_validate(service).model_dump(),
            asset_label=asset.display_name,
        )
        for service, asset in list_services(session, dockyard_id, limit)
    ]


@router.get("/dockyards/{dockyard_id}/observations", response_model=list[ObservationRead])
def read_observations(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[ObservationRead]:
    require_dockyard(dockyard_id, session)
    return list_observations(session, dockyard_id, limit)


@router.get("/dockyards/{dockyard_id}/discoveries", response_model=list[DiscoveryRunRead])
def read_discoveries(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[DiscoveryRunRead]:
    require_dockyard(dockyard_id, session)
    return discovery_runner.list_runs(session, dockyard_id, limit)


@router.post(
    "/dockyards/{dockyard_id}/discoveries",
    response_model=DiscoveryRunRead,
    status_code=status.HTTP_202_ACCEPTED,
    responses={403: {"model": DiscoveryRunRead, "description": "DockGuard denied the target"}},
)
def start_discovery(
    dockyard_id: int,
    payload: DiscoveryCreate,
    session: Session = Depends(get_session),
) -> Response | DiscoveryRunRead:
    """Request a discovery run.

    DockGuard decides here, on the server. A denied request is still stored so
    the attempt is auditable, but no adapter is ever scheduled for it.
    """
    require_dockyard(dockyard_id, session)
    try:
        run, evaluation = discovery_runner.create_run(
            session, dockyard_id, payload.target, payload.adapter, payload.profile
        )
    except discovery_runner.RunRejected as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)
        ) from error

    if not evaluation.allowed:
        return JSONResponse(
            content=jsonable_encoder(DiscoveryRunRead.model_validate(run)),
            status_code=status.HTTP_403_FORBIDDEN,
        )
    discovery_runner.submit_run(run.id)
    return DiscoveryRunRead.model_validate(run)


@router.get("/dockyards/{dockyard_id}/discoveries/{run_id}", response_model=DiscoveryRunRead)
def read_discovery(
    dockyard_id: int, run_id: int, session: Session = Depends(get_session)
) -> DiscoveryRunRead:
    require_dockyard(dockyard_id, session)
    run = discovery_runner.get_run(session, dockyard_id, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery run not found")
    return run


@router.get("/dockyards/{dockyard_id}/evidence", response_model=list[EvidenceRecordRead])
def read_evidence(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[EvidenceRecordRead]:
    require_dockyard(dockyard_id, session)
    statement = (
        select(EvidenceRecord)
        .where(EvidenceRecord.dockyard_id == dockyard_id)
        .order_by(EvidenceRecord.id.desc())
        .limit(limit)
    )
    return list(session.scalars(statement))
