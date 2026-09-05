"""Discovery run orchestration.

The runner owns the whole life of a discovery request: DockGuard evaluation,
adapter invocation, normalization into the Dockyard inventory and evidence
capture. Every path through it ends with a persisted run whose status says
exactly what happened, including the runs that were never allowed to start.
"""

import logging
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import lab
from app.config import get_settings
from app.discovery import registry
from app.discovery.base import (
    AdapterError,
    AdapterRequest,
    AdapterResult,
    Confidence,
    DiscoveredAsset,
    DiscoveredObservation,
    DiscoveryAdapter,
    Profile,
    RunStatus,
)
from app.dockguard import Decision, Evaluation, evaluate, system_resolver
from app.evidence import EVIDENCE_SCHEMA, EvidenceStore
from app.inventory import record_observation, upsert_asset, upsert_service
from app.models import DiscoveryRun, EvidenceRecord
from app.services import scope_rules
from app.targets import Target, TargetKind, normalize_target

logger = logging.getLogger("reddock.discovery")

_settings = get_settings()
_executor = ThreadPoolExecutor(
    max_workers=_settings.max_concurrent_runs, thread_name_prefix="reddock-discovery"
)
_pending: set[Future] = set()

ACTIVE_STATUSES = (str(RunStatus.PENDING), str(RunStatus.RUNNING))


class RunRejected(ValueError):
    """Raised when a run cannot be created at all (bad adapter, profile or load)."""


def create_run(
    session: Session,
    dockyard_id: int,
    requested_target: str,
    adapter_name: str,
    profile_name: str,
) -> tuple[DiscoveryRun, Evaluation]:
    """Evaluate a request and persist it, allowed or denied.

    A denied request is still recorded: an audit trail that only contains the
    requests that succeeded is not an audit trail.
    """
    adapter = registry.get_adapter(adapter_name)
    if adapter is None:
        raise RunRejected(f"Unknown discovery adapter: {adapter_name}")
    profile = adapter.profile(profile_name)
    if profile is None:
        raise RunRejected(f"{adapter.title} has no {profile_name} profile")

    evaluation = evaluate(
        requested_target, scope_rules(session, dockyard_id), resolver=system_resolver
    )
    target = normalize_target(requested_target) if evaluation.allowed else None
    if evaluation.allowed and target is not None and not adapter.supports(target):
        reason = f"{adapter.title} cannot act on a {evaluation.target_kind} target"
        if profile.requires_lab_authorization:
            evaluation = replace(evaluation, decision=Decision.DENIED_POLICY, reason=reason)
        else:
            raise RunRejected(reason)
    if evaluation.allowed and target is not None:
        reason = _single_host_denial(profile, target, evaluation)
        if reason:
            if profile.requires_lab_authorization:
                evaluation = replace(evaluation, decision=Decision.DENIED_POLICY, reason=reason)
            else:
                raise RunRejected(reason)
    if evaluation.allowed and active_run_count(session) >= get_settings().max_concurrent_runs:
        reason = (
            f"RedDock already has {get_settings().max_concurrent_runs} discovery runs in flight"
        )
        if profile.requires_lab_authorization:
            evaluation = replace(evaluation, decision=Decision.DENIED_POLICY, reason=reason)
        else:
            raise RunRejected(reason)

    now = datetime.now(UTC)
    run = DiscoveryRun(
        dockyard_id=dockyard_id,
        adapter=adapter.name,
        adapter_version=adapter.version,
        profile=profile_name,
        requested_target=requested_target,
        normalized_target=evaluation.normalized_target,
        status=str(RunStatus.PENDING if evaluation.allowed else RunStatus.DENIED),
        decision=str(evaluation.decision),
        decision_reason=evaluation.reason[:500],
        completed_at=None if evaluation.allowed else now,
    )
    session.add(run)
    session.flush()
    if profile.requires_lab_authorization:
        if evaluation.allowed:
            policy = lab.check_capability(
                session,
                dockyard_id,
                profile.capability or "",
                action="request",
                discovery_run_id=run.id,
            )
        else:
            policy = lab.record_denial(
                session,
                dockyard_id,
                profile.capability or "",
                action="request",
                reason=evaluation.reason,
                discovery_run_id=run.id,
            )
        if not policy.allowed and evaluation.allowed:
            evaluation = replace(
                evaluation,
                decision=Decision.DENIED_POLICY,
                reason=policy.reason,
            )
            run.status = str(RunStatus.DENIED)
            run.decision = str(evaluation.decision)
            run.decision_reason = evaluation.reason[:500]
            run.completed_at = now
    session.commit()
    session.refresh(run)
    return run, evaluation


def active_run_count(session: Session) -> int:
    statement = (
        select(func.count())
        .select_from(DiscoveryRun)
        .where(DiscoveryRun.status.in_(ACTIVE_STATUSES))
    )
    return session.scalar(statement) or 0


def list_runs(session: Session, dockyard_id: int, limit: int) -> list[DiscoveryRun]:
    statement = (
        select(DiscoveryRun)
        .where(DiscoveryRun.dockyard_id == dockyard_id)
        .order_by(DiscoveryRun.id.desc())
        .limit(limit)
    )
    return list(session.scalars(statement))


def get_run(session: Session, dockyard_id: int, run_id: int) -> DiscoveryRun | None:
    return session.scalar(
        select(DiscoveryRun).where(
            DiscoveryRun.dockyard_id == dockyard_id, DiscoveryRun.id == run_id
        )
    )


def submit_run(run_id: int) -> None:
    """Execute a run on the bounded background pool."""
    future = _executor.submit(execute_run, run_id)
    _pending.add(future)
    future.add_done_callback(_pending.discard)


def execute_run(run_id: int) -> None:
    """Run one allowed discovery to completion. Never raises."""
    from app.database import SessionLocal

    with SessionLocal() as session:
        run = session.get(DiscoveryRun, run_id)
        if run is None or run.status != str(RunStatus.PENDING):
            return
        run.status = str(RunStatus.RUNNING)
        run.started_at = datetime.now(UTC)
        session.commit()

        try:
            _perform(session, run)
        except AdapterError as error:
            _fail(session, run, str(error))
        except Exception:  # a background run must not die silently
            logger.exception("Discovery run %s failed unexpectedly", run_id)
            _fail(session, run, "Discovery failed unexpectedly; see the RedDock container log")


def _perform(session: Session, run: DiscoveryRun) -> None:
    adapter = registry.get_adapter(run.adapter)
    if adapter is None:
        raise AdapterError(f"Adapter {run.adapter} is no longer available")

    profile = adapter.profile(run.profile)
    if profile is None:
        raise AdapterError(f"Adapter {run.adapter} no longer provides profile {run.profile}")

    # DockGuard and lab policy are evaluated again immediately before execution. Scope can
    # change between requesting and starting a run, and the authoritative
    # decision is the one taken with the tool about to be invoked.
    evaluation = evaluate(
        run.requested_target, scope_rules(session, run.dockyard_id), resolver=system_resolver
    )
    run.decision = str(evaluation.decision)
    run.decision_reason = evaluation.reason[:500]
    if not evaluation.allowed:
        if profile.requires_lab_authorization:
            lab.record_denial(
                session,
                run.dockyard_id,
                profile.capability or "",
                action="execute",
                reason=evaluation.reason,
                discovery_run_id=run.id,
            )
        run.status = str(RunStatus.DENIED)
        run.completed_at = datetime.now(UTC)
        session.commit()
        return

    target = normalize_target(run.requested_target)
    reason = _single_host_denial(profile, target, evaluation)
    if reason:
        lab.record_denial(
            session,
            run.dockyard_id,
            profile.capability or "",
            action="execute",
            reason=reason,
            discovery_run_id=run.id,
        )
        run.decision = str(Decision.DENIED_POLICY)
        run.decision_reason = reason[:500]
        run.status = str(RunStatus.DENIED)
        run.completed_at = datetime.now(UTC)
        session.commit()
        return

    if profile.requires_lab_authorization:
        policy = lab.check_capability(
            session,
            run.dockyard_id,
            profile.capability or "",
            action="execute",
            discovery_run_id=run.id,
        )
        if not policy.allowed:
            run.decision = str(Decision.DENIED_POLICY)
            run.decision_reason = policy.reason[:500]
            run.status = str(RunStatus.DENIED)
            run.completed_at = datetime.now(UTC)
            session.commit()
            return

    request = AdapterRequest(
        target=target,
        profile=run.profile,
        resolved_addresses=evaluation.resolved_addresses,
        excluded_addresses=evaluation.excluded_addresses,
        timeout_seconds=get_settings().max_run_seconds,
    )
    result = adapter.run(request)
    observed_at = datetime.now(UTC)
    observations = list(result.observations)
    if evaluation.resolved_addresses:
        observations.insert(0, _resolution_observation(run, evaluation))

    store = EvidenceStore()
    counts = _persist(session, run, adapter, result, observations, observed_at, store)
    _store_evidence(session, run, adapter, result, observations, evaluation, counts, store)

    run.status = str(RunStatus.COMPLETED)
    run.completed_at = datetime.now(UTC)
    run.asset_count, run.service_count, run.observation_count = counts
    session.commit()


def _single_host_denial(
    profile: Profile, target: Target, evaluation: Evaluation
) -> str | None:
    """Return a stable denial when a one-host profile would reach multiple hosts."""
    if not profile.single_host_only:
        return None
    if target.kind in {TargetKind.IPV4_NETWORK, TargetKind.IPV6_NETWORK}:
        return f"{profile.title} is limited to one host; network targets are refused"
    if target.is_named and len(evaluation.resolved_addresses) != 1:
        return (
            f"{profile.title} is limited to one host; {target.host} resolved to "
            f"{len(evaluation.resolved_addresses)} addresses"
        )
    return None


def _persist(
    session: Session,
    run: DiscoveryRun,
    adapter: DiscoveryAdapter,
    result: AdapterResult,
    observations: list[DiscoveredObservation],
    observed_at: datetime,
    store: EvidenceStore,
) -> tuple[int, int, int]:
    asset_ids: dict[str, int] = {}
    service_ids: dict[tuple[str, str, int], int] = {}
    service_count = 0

    for discovered in result.assets:
        asset = upsert_asset(session, run.dockyard_id, discovered, observed_at)
        asset_ids[discovered.identity] = asset.id
        for discovered_service in discovered.services:
            service = upsert_service(session, asset, discovered_service, observed_at)
            service_ids[
                (discovered.identity, discovered_service.transport, discovered_service.port)
            ] = service.id
            service_count += 1

    raw_reference = store.relative_run_path(run.dockyard_id, run.id)
    for discovered_observation in observations:
        asset_id = asset_ids.get(discovered_observation.asset_identity or "")
        service_id = None
        if discovered_observation.asset_identity and discovered_observation.service_port:
            transport, port = discovered_observation.service_port
            service_id = service_ids.get((discovered_observation.asset_identity, transport, port))
        record_observation(
            session,
            dockyard_id=run.dockyard_id,
            run_id=run.id,
            adapter=adapter.name,
            discovered=discovered_observation,
            observed_at=observed_at,
            asset_id=asset_id,
            service_id=service_id,
            raw_reference=raw_reference,
        )

    session.commit()
    return len(result.assets), service_count, len(observations)


def _resolution_observation(run: DiscoveryRun, evaluation: Evaluation) -> DiscoveredObservation:
    addresses = ", ".join(evaluation.resolved_addresses)
    return DiscoveredObservation(
        observation_type="dns_resolution",
        summary=f"{run.normalized_target} resolved to {addresses}",
        confidence=Confidence.OBSERVED,
        detail={"addresses": list(evaluation.resolved_addresses)},
    )


def _store_evidence(
    session: Session,
    run: DiscoveryRun,
    adapter: DiscoveryAdapter,
    result: AdapterResult,
    observations: list[DiscoveredObservation],
    evaluation: Evaluation,
    counts: tuple[int, int, int],
    store: EvidenceStore,
) -> None:
    stored = [
        store.write_raw(
            run.dockyard_id, run.id, artifact.name, artifact.media_type, artifact.content
        )
        for artifact in result.artifacts
    ]
    stored.append(
        store.write_normalized(
            run.dockyard_id,
            run.id,
            {
                "assets": [_asset_document(asset) for asset in result.assets],
                "observations": [
                    {
                        "type": observation.observation_type,
                        "summary": observation.summary,
                        "confidence": str(observation.confidence),
                        "detail": observation.detail,
                    }
                    for observation in observations
                ],
            },
        )
    )
    metadata = {
        "schema": EVIDENCE_SCHEMA,
        "dockyard_id": run.dockyard_id,
        "run_id": run.id,
        "adapter": {
            "name": adapter.name,
            "version": adapter.version,
            "tool_version": result.tool_version,
        },
        "profile": run.profile,
        "requested_target": run.requested_target,
        "normalized_target": run.normalized_target,
        "dockguard": {
            "decision": str(evaluation.decision),
            "reason": evaluation.reason,
            "matched_rule": evaluation.matched_rule,
            "resolved_addresses": list(evaluation.resolved_addresses),
            "excluded_addresses": list(evaluation.excluded_addresses),
        },
        "invocation": list(result.invocation),
        "started_at": _iso(run.started_at),
        "recorded_at": _iso(datetime.now(UTC)),
        "counts": {"assets": counts[0], "services": counts[1], "observations": counts[2]},
        "artifacts": [
            {
                "path": artifact.relative_path,
                "sha256": artifact.sha256,
                "bytes": artifact.size_bytes,
                "truncated": artifact.truncated,
            }
            for artifact in stored
        ],
    }
    stored.append(store.write_metadata(run.dockyard_id, run.id, metadata))

    for artifact in stored:
        session.add(
            EvidenceRecord(
                dockyard_id=run.dockyard_id,
                discovery_run_id=run.id,
                kind=artifact.kind,
                relative_path=artifact.relative_path,
                media_type=artifact.media_type,
                size_bytes=artifact.size_bytes,
                sha256=artifact.sha256,
                truncated=artifact.truncated,
            )
        )
    run.evidence_path = store.relative_run_path(run.dockyard_id, run.id)
    session.commit()


def _iso(moment: datetime | None) -> str | None:
    """Timestamps are stored in UTC; evidence says so explicitly."""
    if moment is None:
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).isoformat()


def _asset_document(asset: DiscoveredAsset) -> dict:
    return {
        "type": str(asset.asset_type),
        "identity": asset.identity,
        "ip_address": asset.ip_address,
        "hostname": asset.hostname,
        "services": [
            {
                "transport": service.transport,
                "port": service.port,
                "state": service.state,
                "service_name": service.service_name,
                "product": service.product,
                "version": service.version,
            }
            for service in asset.services
        ],
    }


def _fail(session: Session, run: DiscoveryRun, message: str) -> None:
    run.status = str(RunStatus.FAILED)
    run.error = message[:500]
    run.completed_at = datetime.now(UTC)
    session.commit()


def recover_interrupted_runs(session: Session) -> int:
    """Mark runs that a restart interrupted, rather than pretending they finished."""
    interrupted = list(
        session.scalars(select(DiscoveryRun).where(DiscoveryRun.status.in_(ACTIVE_STATUSES)))
    )
    for run in interrupted:
        _fail(session, run, "Interrupted by a RedDock restart")
    return len(interrupted)
