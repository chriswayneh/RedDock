from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import lab
from app.config import get_settings
from app.correlation import runner as correlation_runner
from app.database import get_session
from app.detection import registry as detection_registry
from app.detection import runner as detection_runner
from app.detection.base import FindingStatus, Severity
from app.discovery import registry
from app.discovery import runner as discovery_runner
from app.dockguard import Evaluation, ScopeRejected, evaluate, system_resolver
from app.findings import get_finding, list_evidence, list_findings, set_status
from app.intelligence import runner as intelligence_runner
from app.inventory import get_asset, list_assets, list_observations, list_services
from app.lab_capabilities import CAPABILITIES
from app.models import Asset, Dockyard, EvidenceRecord, Finding, FindingEvidence, Service
from app.reporting import runner as reporting_runner
from app.schemas import (
    AdapterRead,
    AssetDetailRead,
    AssetRead,
    CorrelationCreate,
    CorrelationRunRead,
    DetectionCreate,
    DetectionRunRead,
    DetectorRead,
    DiscoveryCreate,
    DiscoveryRunRead,
    DockyardCreate,
    DockyardRead,
    EvidenceRecordRead,
    FindingDetailRead,
    FindingEvidenceRead,
    FindingRead,
    FindingStatusUpdate,
    HealthRead,
    IntelligenceApprovalCreate,
    IntelligenceCreate,
    IntelligenceProviderRead,
    IntelligenceRunRead,
    LabAuditEventRead,
    LabAuthorizationCreate,
    LabAuthorizationRead,
    LabCapabilityRead,
    LabRevokeCreate,
    LabStatusRead,
    ObservationRead,
    ProfileRead,
    RedPathGraphRead,
    ReportCreate,
    ReportRunRead,
    ScopeEntryCreate,
    ScopeEntryRead,
    ScopeEvaluateRequest,
    ScopeEvaluationRead,
    ServiceRead,
    ServiceRowRead,
    ValidationApprovalCreate,
    ValidationRunRead,
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
from app.validation import runner as validation_runner

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


@router.get("/detectors", response_model=list[DetectorRead])
def read_detectors() -> list[DetectorRead]:
    """The fixed set of detectors. Nothing is loaded at runtime."""
    return [
        DetectorRead(
            id=detector.id,
            version=detector.version,
            title=detector.title,
            description=detector.description,
            consumes=list(detector.consumes),
        )
        for detector in detection_registry.available_detectors()
    ]


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


@router.get("/lab/status", response_model=LabStatusRead)
def read_lab_status() -> LabStatusRead:
    """Describe the fixed lab boundary without exposing process configuration."""
    settings = get_settings()
    return LabStatusRead(
        deployment_enabled=settings.lab_mode_enabled,
        acknowledgement=lab.LAB_ACKNOWLEDGEMENT,
        max_authorization_minutes=settings.max_lab_authorization_minutes,
        capabilities=[LabCapabilityRead(**asdict(item)) for item in CAPABILITIES],
    )


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


@router.get(
    "/dockyards/{dockyard_id}/lab/authorizations",
    response_model=list[LabAuthorizationRead],
)
def read_lab_authorizations(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[LabAuthorizationRead]:
    require_dockyard(dockyard_id, session)
    return lab.list_authorizations(session, dockyard_id, limit)


@router.post(
    "/dockyards/{dockyard_id}/lab/authorizations",
    response_model=LabAuthorizationRead,
    status_code=status.HTTP_201_CREATED,
)
def authorize_lab_capability(
    dockyard_id: int,
    payload: LabAuthorizationCreate,
    session: Session = Depends(get_session),
) -> LabAuthorizationRead:
    require_dockyard(dockyard_id, session)
    try:
        authorization, decision = lab.create_authorization(
            session,
            dockyard_id,
            payload.capability,
            payload.acknowledgement,
            payload.note,
            payload.duration_minutes,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(error)
        ) from error
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)
    return LabAuthorizationRead.model_validate(authorization)


@router.post(
    "/dockyards/{dockyard_id}/lab/authorizations/{authorization_id}/revoke",
    response_model=LabAuthorizationRead,
)
def revoke_lab_capability(
    dockyard_id: int,
    authorization_id: int,
    payload: LabRevokeCreate,
    session: Session = Depends(get_session),
) -> LabAuthorizationRead:
    require_dockyard(dockyard_id, session)
    authorization = lab.revoke_authorization(session, dockyard_id, authorization_id)
    if authorization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorization not found")
    return LabAuthorizationRead.model_validate(authorization)


@router.get(
    "/dockyards/{dockyard_id}/lab/audit",
    response_model=list[LabAuditEventRead],
)
def read_lab_audit(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[LabAuditEventRead]:
    require_dockyard(dockyard_id, session)
    return lab.list_audit_events(session, dockyard_id, limit)


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


@router.get("/dockyards/{dockyard_id}/detections", response_model=list[DetectionRunRead])
def read_detections(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[DetectionRunRead]:
    require_dockyard(dockyard_id, session)
    return detection_runner.list_runs(session, dockyard_id, limit)


@router.post(
    "/dockyards/{dockyard_id}/detections",
    response_model=DetectionRunRead,
    status_code=status.HTTP_201_CREATED,
)
def start_detection(
    dockyard_id: int,
    payload: DetectionCreate,
    session: Session = Depends(get_session),
) -> DetectionRunRead:
    """Run every registered detector over what this Dockyard already recorded.

    Detection reads stored state and contacts nothing, so it runs to completion
    within the request and the response describes a finished run. The request
    body is empty by design: there is no target and no operator-supplied option
    for a detector to act on.
    """
    require_dockyard(dockyard_id, session)
    try:
        run = detection_runner.start_detection(session, dockyard_id)
    except detection_runner.RunRejected as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    return DetectionRunRead.model_validate(run)


@router.get("/dockyards/{dockyard_id}/detections/{run_id}", response_model=DetectionRunRead)
def read_detection(
    dockyard_id: int, run_id: int, session: Session = Depends(get_session)
) -> DetectionRunRead:
    require_dockyard(dockyard_id, session)
    run = detection_runner.get_run(session, dockyard_id, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection run not found")
    return run


@router.get("/dockyards/{dockyard_id}/correlations", response_model=list[CorrelationRunRead])
def read_correlations(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[CorrelationRunRead]:
    require_dockyard(dockyard_id, session)
    return correlation_runner.list_runs(session, dockyard_id, limit)


@router.post(
    "/dockyards/{dockyard_id}/correlations",
    response_model=CorrelationRunRead,
    status_code=status.HTTP_201_CREATED,
)
def start_correlation(
    dockyard_id: int,
    payload: CorrelationCreate,
    session: Session = Depends(get_session),
) -> CorrelationRunRead:
    """Relate stored state only; the deliberately empty body selects nothing."""
    require_dockyard(dockyard_id, session)
    try:
        return correlation_runner.start_correlation(session, dockyard_id)
    except correlation_runner.RunRejected as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/dockyards/{dockyard_id}/redpath", response_model=RedPathGraphRead)
def read_redpath(
    dockyard_id: int, session: Session = Depends(get_session)
) -> RedPathGraphRead:
    require_dockyard(dockyard_id, session)
    return RedPathGraphRead.model_validate(correlation_runner.graph(session, dockyard_id))


@router.get("/intelligence/provider", response_model=IntelligenceProviderRead)
def read_intelligence_provider() -> IntelligenceProviderRead:
    """Describe configured capability without ever exposing a credential."""
    return IntelligenceProviderRead.model_validate(intelligence_runner.provider_status())


@router.get(
    "/dockyards/{dockyard_id}/intelligence", response_model=list[IntelligenceRunRead]
)
def read_intelligence_runs(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[IntelligenceRunRead]:
    require_dockyard(dockyard_id, session)
    return intelligence_runner.list_runs(session, dockyard_id, limit)


@router.post(
    "/dockyards/{dockyard_id}/intelligence",
    response_model=IntelligenceRunRead,
    status_code=status.HTTP_201_CREATED,
)
def create_intelligence_run(
    dockyard_id: int,
    payload: IntelligenceCreate,
    session: Session = Depends(get_session),
) -> IntelligenceRunRead:
    """Create and retain the exact packet; do not contact a provider."""
    require_dockyard(dockyard_id, session)
    try:
        return intelligence_runner.create_run(session, dockyard_id)
    except intelligence_runner.RunRejected as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.post(
    "/dockyards/{dockyard_id}/intelligence/{run_id}/approve",
    response_model=IntelligenceRunRead,
)
def approve_intelligence_run(
    dockyard_id: int,
    run_id: int,
    payload: IntelligenceApprovalCreate,
    session: Session = Depends(get_session),
) -> IntelligenceRunRead:
    """Approve sending only the retained packet to its bound provider."""
    require_dockyard(dockyard_id, session)
    try:
        return intelligence_runner.approve_run(session, dockyard_id, run_id, payload.note)
    except intelligence_runner.RunRejected as error:
        message = str(error)
        code = (
            status.HTTP_404_NOT_FOUND
            if message == "Intelligence run not found"
            else status.HTTP_409_CONFLICT
        )
        raise HTTPException(status_code=code, detail=message) from error


@router.get("/dockyards/{dockyard_id}/reports", response_model=list[ReportRunRead])
def read_reports(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[ReportRunRead]:
    require_dockyard(dockyard_id, session)
    return reporting_runner.list_runs(session, dockyard_id, limit)


@router.post(
    "/dockyards/{dockyard_id}/reports",
    response_model=ReportRunRead,
    status_code=status.HTTP_201_CREATED,
)
def create_report(
    dockyard_id: int,
    payload: ReportCreate,
    session: Session = Depends(get_session),
) -> ReportRunRead:
    """Snapshot all retained state; the empty request chooses no target or path."""
    require_dockyard(dockyard_id, session)
    try:
        return reporting_runner.start_report(session, dockyard_id)
    except reporting_runner.ReportRejected as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/dockyards/{dockyard_id}/reports/{run_id}", response_model=ReportRunRead)
def read_report(
    dockyard_id: int, run_id: int, session: Session = Depends(get_session)
) -> ReportRunRead:
    require_dockyard(dockyard_id, session)
    run = reporting_runner.get_run(session, dockyard_id, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report run not found")
    return run


def _report_artifact(dockyard_id: int, run_id: int, artifact: str, session: Session):
    require_dockyard(dockyard_id, session)
    run = reporting_runner.get_run(session, dockyard_id, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report run not found")
    try:
        return reporting_runner.artifact_path(run, artifact)
    except reporting_runner.ReportRejected as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/dockyards/{dockyard_id}/reports/{run_id}/technical")
def read_technical_report(
    dockyard_id: int, run_id: int, session: Session = Depends(get_session)
):
    path = _report_artifact(dockyard_id, run_id, "technical", session)
    return FileResponse(path, media_type="text/markdown; charset=utf-8")


@router.get("/dockyards/{dockyard_id}/reports/{run_id}/executive")
def read_executive_report(
    dockyard_id: int, run_id: int, session: Session = Depends(get_session)
):
    path = _report_artifact(dockyard_id, run_id, "executive", session)
    return FileResponse(path, media_type="text/markdown; charset=utf-8")


@router.get("/dockyards/{dockyard_id}/reports/{run_id}/manifest")
def read_report_manifest(
    dockyard_id: int, run_id: int, session: Session = Depends(get_session)
):
    path = _report_artifact(dockyard_id, run_id, "manifest", session)
    return FileResponse(path, media_type="application/json")


@router.get("/dockyards/{dockyard_id}/reports/{run_id}/dockpack")
def download_dockpack(
    dockyard_id: int, run_id: int, session: Session = Depends(get_session)
):
    path = _report_artifact(dockyard_id, run_id, "dockpack", session)
    return FileResponse(
        path,
        media_type="application/zip",
        filename=f"reddock-dockyard-{dockyard_id}-report-{run_id}.dockpack.zip",
    )


@router.get("/dockyards/{dockyard_id}/validations", response_model=list[ValidationRunRead])
def read_validations(
    dockyard_id: int, limit: int = ListLimit, session: Session = Depends(get_session)
) -> list[ValidationRunRead]:
    require_dockyard(dockyard_id, session)
    return validation_runner.list_runs(session, dockyard_id, limit)


@router.post(
    "/dockyards/{dockyard_id}/findings/{finding_id}/validations",
    response_model=ValidationRunRead,
    status_code=status.HTTP_201_CREATED,
)
def request_validation(
    dockyard_id: int, finding_id: int, session: Session = Depends(get_session)
) -> ValidationRunRead:
    """Request, but do not yet run, a finding's one safe validation profile."""
    require_dockyard(dockyard_id, session)
    finding = get_finding(session, dockyard_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    try:
        return validation_runner.create_run(session, dockyard_id, finding)
    except validation_runner.ValidationRejected as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get(
    "/dockyards/{dockyard_id}/validations/{run_id}", response_model=ValidationRunRead
)
def read_validation(
    dockyard_id: int, run_id: int, session: Session = Depends(get_session)
) -> ValidationRunRead:
    require_dockyard(dockyard_id, session)
    run = validation_runner.get_run(session, dockyard_id, run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Validation run not found"
        )
    return run


@router.post(
    "/dockyards/{dockyard_id}/validations/{run_id}/approve",
    response_model=ValidationRunRead,
    responses={403: {"model": ValidationRunRead, "description": "DockGuard denied the recheck"}},
)
def approve_validation(
    dockyard_id: int,
    run_id: int,
    payload: ValidationApprovalCreate,
    session: Session = Depends(get_session),
) -> Response | ValidationRunRead:
    """Apply the explicit local approval gate, then re-evaluate DockGuard."""
    require_dockyard(dockyard_id, session)
    try:
        run = validation_runner.approve_run(session, dockyard_id, run_id, payload.note)
    except validation_runner.ValidationRejected as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    if run.status == validation_runner.DENIED:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=jsonable_encoder(ValidationRunRead.model_validate(run)),
        )
    return ValidationRunRead.model_validate(run)


@router.get("/dockyards/{dockyard_id}/findings", response_model=list[FindingRead])
def read_findings(
    dockyard_id: int,
    finding_status: FindingStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = Query(default=None),
    detector: str | None = Query(default=None, max_length=48),
    asset_id: int | None = Query(default=None, ge=1),
    service_id: int | None = Query(default=None, ge=1),
    limit: int = ListLimit,
    session: Session = Depends(get_session),
) -> list[FindingRead]:
    """Findings for one Dockyard.

    Every filter is validated before it reaches a query, and the Dockyard is
    always part of that query: a finding is never reachable from another
    workspace.
    """
    require_dockyard(dockyard_id, session)
    rows = list_findings(
        session,
        dockyard_id,
        limit,
        status=str(finding_status) if finding_status else None,
        severity=str(severity) if severity else None,
        detector=detector,
        asset_id=asset_id,
        service_id=service_id,
    )
    labels = _subject_labels(session, rows)
    counts = _evidence_counts(session, rows)
    return [_finding_body(FindingRead, finding, labels, counts) for finding in rows]


@router.get("/dockyards/{dockyard_id}/findings/{finding_id}", response_model=FindingDetailRead)
def read_finding(
    dockyard_id: int, finding_id: int, session: Session = Depends(get_session)
) -> FindingDetailRead:
    require_dockyard(dockyard_id, session)
    finding = get_finding(session, dockyard_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    evidence = list_evidence(session, finding.id)
    labels = _subject_labels(session, [finding])
    detail = _finding_body(FindingDetailRead, finding, labels, {finding.id: len(evidence)})
    validations = [
        ValidationRunRead.model_validate(run)
        for run in validation_runner.list_for_finding(session, finding.id)
    ]
    return detail.model_copy(
        update={"evidence": _evidence_bodies(session, evidence), "validations": validations}
    )


@router.patch("/dockyards/{dockyard_id}/findings/{finding_id}", response_model=FindingDetailRead)
def update_finding(
    dockyard_id: int,
    finding_id: int,
    payload: FindingStatusUpdate,
    session: Session = Depends(get_session),
) -> FindingDetailRead:
    """Record an operator decision about a finding.

    A finding is never deleted here. Suppressing or accepting one keeps it, its
    history and its evidence; it only changes what RedDock treats as open.
    """
    require_dockyard(dockyard_id, session)
    finding = get_finding(session, dockyard_id, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    set_status(session, finding, payload.status, payload.note)
    return read_finding(dockyard_id, finding_id, session)


def _subject_labels(session: Session, rows: list[Finding]) -> dict[str, dict[int, str]]:
    """Readable asset and service labels for the findings being returned."""
    asset_ids = {finding.asset_id for finding in rows if finding.asset_id}
    service_ids = {finding.service_id for finding in rows if finding.service_id}
    assets: dict[int, str] = {}
    services: dict[int, str] = {}
    if asset_ids:
        for asset in session.scalars(select(Asset).where(Asset.id.in_(asset_ids))):
            assets[asset.id] = asset.display_name
    if service_ids:
        for service in session.scalars(select(Service).where(Service.id.in_(service_ids))):
            services[service.id] = f"{service.transport.upper()}/{service.port}"
    return {"assets": assets, "services": services}


def _evidence_counts(session: Session, rows: list[Finding]) -> dict[int, int]:
    identifiers = [finding.id for finding in rows]
    if not identifiers:
        return {}
    statement = (
        select(FindingEvidence.finding_id, func.count())
        .where(FindingEvidence.finding_id.in_(identifiers))
        .group_by(FindingEvidence.finding_id)
    )
    return {finding_id: count for finding_id, count in session.execute(statement)}


def _finding_body(model, finding: Finding, labels: dict, counts: dict[int, int]):
    body = model.model_validate(finding)
    return body.model_copy(
        update={
            "asset_label": labels["assets"].get(finding.asset_id),
            "service_endpoint": labels["services"].get(finding.service_id),
            "evidence_count": counts.get(finding.id, 0),
        }
    )


def _evidence_bodies(
    session: Session, evidence: list[FindingEvidence]
) -> list[FindingEvidenceRead]:
    """Evidence rows with the RedLedger artifact and hash behind each one."""
    record_ids = {row.evidence_record_id for row in evidence if row.evidence_record_id}
    records: dict[int, EvidenceRecord] = {}
    if record_ids:
        records = {
            record.id: record
            for record in session.scalars(
                select(EvidenceRecord).where(EvidenceRecord.id.in_(record_ids))
            )
        }
    bodies = []
    for row in evidence:
        record = records.get(row.evidence_record_id) if row.evidence_record_id else None
        body = FindingEvidenceRead.model_validate(row)
        bodies.append(
            body.model_copy(
                update={
                    "evidence_path": record.relative_path if record else None,
                    "sha256": record.sha256 if record else None,
                }
            )
        )
    return bodies
