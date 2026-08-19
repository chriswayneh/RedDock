"""Detection run orchestration.

The runner owns everything a detector is not trusted with: building the
snapshot, validating what comes back, deciding identity, reconciling against
what is already known, resolving what is no longer reproduced and writing
evidence. A detector only decides what it concluded.

A detection run is synchronous. It contacts nothing, so there is nothing to wait
on and no reason to leave a run in flight across a restart; when the request
returns, the run is finished and its evidence is on disk.

Two rules hold every path through here together:

- A finding must cite at least one observation from the snapshot it was drawn
  from. A conclusion nothing supports is refused, not stored with a caveat.
- A detector that returns anything invalid is failed as a whole and its results
  are discarded. Half-trusting a detector that has already demonstrated it is
  wrong about its own output is not a safe default, and a failed detector
  resolves nothing.
"""

import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.detection import registry
from app.detection.base import (
    DetectedFinding,
    DetectionContext,
    DetectionRunStatus,
    Detector,
    FindingCategory,
    FindingConfidence,
    Severity,
)
from app.detection.context import build_context
from app.detection.enrichment import load_enrichment
from app.detection.fingerprint import fingerprint as compute_fingerprint
from app.evidence import DETECTION_SCOPE, EVIDENCE_SCHEMA, EvidenceStore
from app.findings import attach_evidence, resolve_absent, upsert_finding
from app.models import DetectionRun, Observation

logger = logging.getLogger("reddock.detection")

ACTIVE_STATUSES = (str(DetectionRunStatus.PENDING), str(DetectionRunStatus.RUNNING))

_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MAX_TITLE = 200
_MAX_DESCRIPTION = 4_000
_MAX_REMEDIATION = 2_000
_MAX_SCOPE_KEY = 120


class RunRejected(ValueError):
    """Raised when a detection run cannot be started at all."""


class DetectorOutputError(ValueError):
    """Raised when a detector returns something RedDock will not store."""


@dataclass(slots=True)
class _DetectorOutcome:
    detector: Detector
    findings: tuple[DetectedFinding, ...] = ()
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def create_run(session: Session, dockyard_id: int) -> DetectionRun:
    """Persist a pending detection run, refusing to overlap with another."""
    if active_run_count(session, dockyard_id):
        raise RunRejected("A detection run is already in flight for this Dockyard")
    run = DetectionRun(dockyard_id=dockyard_id, status=str(DetectionRunStatus.PENDING))
    session.add(run)
    session.commit()
    session.refresh(run)
    return run


def start_detection(session: Session, dockyard_id: int) -> DetectionRun:
    """Create and execute one detection run over a Dockyard's recorded state."""
    run = create_run(session, dockyard_id)
    return execute_run(session, run)


def active_run_count(session: Session, dockyard_id: int) -> int:
    statement = (
        select(func.count())
        .select_from(DetectionRun)
        .where(
            DetectionRun.dockyard_id == dockyard_id,
            DetectionRun.status.in_(ACTIVE_STATUSES),
        )
    )
    return session.scalar(statement) or 0


def list_runs(session: Session, dockyard_id: int, limit: int) -> list[DetectionRun]:
    statement = (
        select(DetectionRun)
        .where(DetectionRun.dockyard_id == dockyard_id)
        .order_by(DetectionRun.id.desc())
        .limit(limit)
    )
    return list(session.scalars(statement))


def get_run(session: Session, dockyard_id: int, run_id: int) -> DetectionRun | None:
    return session.scalar(
        select(DetectionRun).where(
            DetectionRun.dockyard_id == dockyard_id, DetectionRun.id == run_id
        )
    )


def recover_interrupted_runs(session: Session) -> int:
    """Mark detection runs that a restart interrupted.

    A detection run completes inside its request, so one still marked active at
    startup did not finish. Saying so matters twice over: the record is honest,
    and an overlapping run is refused while one looks active, so a run left
    behind by a crash would otherwise block this Dockyard's detection for good.
    """
    interrupted = list(
        session.scalars(select(DetectionRun).where(DetectionRun.status.in_(ACTIVE_STATUSES)))
    )
    for run in interrupted:
        run.status = str(DetectionRunStatus.FAILED)
        run.error = "Interrupted by a RedDock restart"
        run.completed_at = datetime.now(UTC)
    session.commit()
    return len(interrupted)


def execute_run(session: Session, run: DetectionRun) -> DetectionRun:
    """Run every registered detector over the Dockyard snapshot. Never raises."""
    run.status = str(DetectionRunStatus.RUNNING)
    run.started_at = datetime.now(UTC)
    session.commit()

    try:
        return _perform(session, run)
    except Exception:  # a detection run must not leave the record ambiguous
        logger.exception("Detection run %s failed unexpectedly", run.id)
        run.status = str(DetectionRunStatus.FAILED)
        run.error = "Detection failed unexpectedly; see the RedDock container log"
        run.completed_at = datetime.now(UTC)
        session.commit()
        return run


def _perform(session: Session, run: DetectionRun) -> DetectionRun:
    enrichment, warning = load_enrichment()
    context = build_context(session, run.dockyard_id, enrichment=enrichment)
    observations = _observation_rows(session, context)

    outcomes = [_run_detector(detector, context) for detector in registry.available_detectors()]
    stored, new_count, reproduced = _store(session, run, context, observations, outcomes)
    resolved = _resolve(session, run, outcomes, reproduced)

    run.status = _status(outcomes)
    run.error = _error(outcomes)
    run.detectors = [_detector_document(outcome) for outcome in outcomes]
    run.enrichment = {
        "id": enrichment.id,
        "version": enrichment.version,
        "available": enrichment.available,
        "warning": warning,
    }
    run.asset_count = len(context.assets)
    run.service_count = sum(len(asset.services) for asset in context.assets)
    run.observation_count = len(context.observations)
    run.finding_count = len(stored)
    run.new_finding_count = new_count
    run.resolved_finding_count = len(resolved)
    session.commit()

    _store_evidence(session, run, context, stored, resolved)
    session.commit()
    return run


def _run_detector(detector: Detector, context: DetectionContext) -> _DetectorOutcome:
    """Run one detector in isolation.

    A detector that raises, or returns something invalid, fails on its own. The
    other detectors still run, and a failed detector contributes no findings and
    resolves none of its earlier ones.
    """
    try:
        produced = detector.detect(context)
    except Exception as error:  # a detector must not be able to stop the run
        logger.warning("Detector %s failed: %s", detector.id, error)
        return _DetectorOutcome(detector=detector, error=_describe(error))

    try:
        return _DetectorOutcome(detector=detector, findings=_validated(detector, produced, context))
    except DetectorOutputError as error:
        logger.warning("Detector %s returned output RedDock refused: %s", detector.id, error)
        return _DetectorOutcome(detector=detector, error=str(error))


def _validated(
    detector: Detector, produced: object, context: DetectionContext
) -> tuple[DetectedFinding, ...]:
    """Check everything a detector claimed before any of it is believed."""
    settings = get_settings()
    if not isinstance(produced, tuple | list):
        raise DetectorOutputError("A detector must return a sequence of findings")
    if len(produced) > settings.max_findings_per_detector:
        raise DetectorOutputError(
            f"A detector may return at most {settings.max_findings_per_detector} findings "
            f"in one run; {detector.id} returned {len(produced)}"
        )

    known_observations = {observation.id for observation in context.observations}
    for finding in produced:
        if not isinstance(finding, DetectedFinding):
            raise DetectorOutputError("A detector returned something that is not a finding")
        if not _RULE_ID.match(finding.rule_id):
            raise DetectorOutputError(f"Unusable rule id: {finding.rule_id!r}")
        if not finding.title.strip() or len(finding.title) > _MAX_TITLE:
            raise DetectorOutputError(f"{finding.rule_id} has an unusable title")
        if not finding.description.strip() or len(finding.description) > _MAX_DESCRIPTION:
            raise DetectorOutputError(f"{finding.rule_id} has an unusable description")
        if finding.remediation is not None and len(finding.remediation) > _MAX_REMEDIATION:
            raise DetectorOutputError(f"{finding.rule_id} has over-long remediation guidance")
        if len(finding.scope_key) > _MAX_SCOPE_KEY:
            raise DetectorOutputError(f"{finding.rule_id} has an over-long scope key")
        if not isinstance(finding.severity, Severity):
            raise DetectorOutputError(f"{finding.rule_id} has an unknown severity")
        if not isinstance(finding.confidence, FindingConfidence):
            raise DetectorOutputError(f"{finding.rule_id} has an unknown confidence")
        if not isinstance(finding.category, FindingCategory):
            raise DetectorOutputError(f"{finding.rule_id} has an unknown category")
        _check_subject(finding, context)
        _check_evidence(finding, known_observations, settings.max_evidence_per_finding)
        _check_detail(finding)
    return tuple(sorted(produced, key=lambda item: _order_key(item, context)))


def _check_subject(finding: DetectedFinding, context: DetectionContext) -> None:
    """A finding may only be about something in the snapshot it was given."""
    asset = context.asset(finding.asset_id)
    if finding.asset_id is not None and asset is None:
        raise DetectorOutputError(f"{finding.rule_id} names an asset outside this Dockyard")
    if finding.service_id is None:
        return
    service = context.service(finding.service_id)
    if service is None:
        raise DetectorOutputError(f"{finding.rule_id} names a service outside this Dockyard")
    if asset is not None and service.asset_id != asset.id:
        raise DetectorOutputError(f"{finding.rule_id} names a service on a different asset")


def _check_evidence(finding: DetectedFinding, known: set[int], limit: int) -> None:
    if not finding.evidence_observation_ids:
        raise DetectorOutputError(f"{finding.rule_id} cites no observation")
    if len(finding.evidence_observation_ids) > limit:
        raise DetectorOutputError(f"{finding.rule_id} cites more than {limit} observations")
    unknown = set(finding.evidence_observation_ids) - known
    if unknown:
        raise DetectorOutputError(
            f"{finding.rule_id} cites observations outside this Dockyard: {sorted(unknown)}"
        )


def _check_detail(finding: DetectedFinding) -> None:
    if not isinstance(finding.detail, dict):
        raise DetectorOutputError(f"{finding.rule_id} has a detail that is not an object")
    try:
        json.dumps(finding.detail, sort_keys=True)
    except (TypeError, ValueError) as error:
        raise DetectorOutputError(f"{finding.rule_id} has a detail RedDock cannot store") from error


def _order_key(finding: DetectedFinding, context: DetectionContext) -> tuple:
    """A stable order, so the same data always produces the same run."""
    asset = context.asset(finding.asset_id)
    service = context.service(finding.service_id)
    return (
        finding.rule_id,
        asset.identity if asset else "",
        service.transport if service else "",
        service.port if service else 0,
        finding.scope_key,
    )


def _store(
    session: Session,
    run: DetectionRun,
    context: DetectionContext,
    observations: dict[int, Observation],
    outcomes: list[_DetectorOutcome],
) -> tuple[list[tuple[DetectedFinding, str, int]], int, dict[str, set[str]]]:
    """Reconcile every accepted finding, returning what was stored."""
    stored: list[tuple[DetectedFinding, str, int]] = []
    reproduced: dict[str, set[str]] = {}
    new_count = 0

    for outcome in outcomes:
        detector = outcome.detector
        reproduced.setdefault(detector.id, set())
        if not outcome.ok:
            continue
        for detected in outcome.findings:
            asset = context.asset(detected.asset_id)
            service = context.service(detected.service_id)
            identity = compute_fingerprint(
                detector=detector.id,
                rule_id=detected.rule_id,
                asset_type=asset.asset_type if asset else None,
                asset_identity=asset.identity if asset else None,
                transport=service.transport if service else None,
                port=service.port if service else None,
                scope_key=detected.scope_key,
            )
            finding, created = upsert_finding(
                session,
                dockyard_id=run.dockyard_id,
                detection_run_id=run.id,
                detector_id=detector.id,
                detector_version=detector.version,
                fingerprint=identity,
                detected=detected,
                seen_at=context.generated_at,
            )
            attach_evidence(
                session,
                finding=finding,
                detection_run_id=run.id,
                observations=observations,
                observation_ids=detected.evidence_observation_ids,
            )
            reproduced[detector.id].add(identity)
            stored.append((detected, identity, finding.id))
            new_count += 1 if created else 0
    session.commit()
    return stored, new_count, reproduced


def _resolve(
    session: Session,
    run: DetectionRun,
    outcomes: list[_DetectorOutcome],
    reproduced: dict[str, set[str]],
) -> list[dict[str, str]]:
    """Close out what a successful detector no longer reproduces."""
    resolved: list[dict[str, str]] = []
    for outcome in outcomes:
        if not outcome.ok:
            continue
        for finding in resolve_absent(
            session,
            dockyard_id=run.dockyard_id,
            detector_id=outcome.detector.id,
            reproduced=reproduced.get(outcome.detector.id, set()),
            resolved_at=datetime.now(UTC),
        ):
            resolved.append(
                {
                    "fingerprint": finding.fingerprint,
                    "detector": finding.detector,
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                }
            )
    session.commit()
    return resolved


def _store_evidence(
    session: Session,
    run: DetectionRun,
    context: DetectionContext,
    stored: list[tuple[DetectedFinding, str, int]],
    resolved: list[dict[str, str]],
) -> None:
    store = EvidenceStore()
    result = {
        "schema": EVIDENCE_SCHEMA,
        "findings": [
            _finding_document(detected, identity, finding_id, context)
            for detected, identity, finding_id in stored
        ],
        "resolved": sorted(resolved, key=lambda item: item["fingerprint"]),
    }
    normalized = store.write_normalized(run.dockyard_id, run.id, result, DETECTION_SCOPE)
    metadata = {
        "schema": EVIDENCE_SCHEMA,
        "kind": "detection",
        "dockyard_id": run.dockyard_id,
        "run_id": run.id,
        "detectors": run.detectors,
        "enrichment": run.enrichment,
        "inputs": {
            "assets": run.asset_count,
            "services": run.service_count,
            "observations": run.observation_count,
        },
        "counts": {
            "findings": run.finding_count,
            "new": run.new_finding_count,
            "resolved": run.resolved_finding_count,
        },
        "status": run.status,
        "started_at": _iso(run.started_at),
        "recorded_at": _iso(datetime.now(UTC)),
        "artifacts": [
            {
                "path": normalized.relative_path,
                "sha256": normalized.sha256,
                "bytes": normalized.size_bytes,
            }
        ],
    }
    written = store.write_metadata(run.dockyard_id, run.id, metadata, DETECTION_SCOPE)

    run.evidence_path = store.relative_run_path(run.dockyard_id, run.id, DETECTION_SCOPE)
    run.result_sha256 = normalized.sha256
    run.metadata_sha256 = written.sha256
    run.completed_at = datetime.now(UTC)


def _finding_document(
    detected: DetectedFinding, identity: str, finding_id: int, context: DetectionContext
) -> dict:
    asset = context.asset(detected.asset_id)
    service = context.service(detected.service_id)
    return {
        "id": finding_id,
        "fingerprint": identity,
        "rule_id": detected.rule_id,
        "title": detected.title,
        "category": str(detected.category),
        "severity": str(detected.severity),
        "confidence": str(detected.confidence),
        "asset": asset.identity if asset else None,
        "service": service.endpoint if service else None,
        "observations": list(detected.evidence_observation_ids),
        "cve_references": [reference.document() for reference in detected.cve_references],
        "detail": detected.detail,
    }


def _detector_document(outcome: _DetectorOutcome) -> dict:
    return {
        "id": outcome.detector.id,
        "version": outcome.detector.version,
        "status": "completed" if outcome.ok else "failed",
        "findings": len(outcome.findings),
        "error": outcome.error,
    }


def _observation_rows(session: Session, context: DetectionContext) -> dict[int, Observation]:
    """The observation rows behind the snapshot, for evidence linking."""
    identifiers = [observation.id for observation in context.observations]
    if not identifiers:
        return {}
    rows = session.scalars(
        select(Observation).where(
            Observation.dockyard_id == context.dockyard_id, Observation.id.in_(identifiers)
        )
    )
    return {row.id: row for row in rows}


def _status(outcomes: list[_DetectorOutcome]) -> str:
    failed = [outcome for outcome in outcomes if not outcome.ok]
    if not failed:
        return str(DetectionRunStatus.COMPLETED)
    if len(failed) == len(outcomes):
        return str(DetectionRunStatus.FAILED)
    return str(DetectionRunStatus.PARTIAL)


def _error(outcomes: list[_DetectorOutcome]) -> str | None:
    failed = [f"{outcome.detector.id}: {outcome.error}" for outcome in outcomes if not outcome.ok]
    return "; ".join(failed)[:500] if failed else None


def _describe(error: Exception) -> str:
    return f"{type(error).__name__}: {error}"[:400]


def _iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).isoformat()
