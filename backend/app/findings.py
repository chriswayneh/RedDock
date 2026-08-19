"""Persistence rules for findings.

Findings are reconciled, observations are not. An observation is a dated
statement that is never revisited; a finding is the current conclusion about one
underlying issue, so a repeated detection of the same issue updates the row it
already has. Its identity is its fingerprint, its history is `first_seen`,
`last_seen` and `resolved_at`, and its support is the evidence rows that point
back at the observations it was drawn from.

Nothing here deletes a finding. An issue that a later run no longer reproduces
is resolved, which is a fact worth keeping; removing the row would erase the
part of the record that shows it was ever true.
"""

from datetime import datetime

from sqlalchemy import Select, case, func, select
from sqlalchemy.orm import Session

from app.detection.base import (
    OPERATOR_OWNED_STATUSES,
    DetectedFinding,
    FindingStatus,
)
from app.models import EvidenceRecord, Finding, FindingEvidence, Observation

#: Most severe first, so a findings list opens on what matters.
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}


def upsert_finding(
    session: Session,
    *,
    dockyard_id: int,
    detection_run_id: int,
    detector_id: str,
    detector_version: str,
    fingerprint: str,
    detected: DetectedFinding,
    seen_at: datetime,
) -> tuple[Finding, bool]:
    """Store one detected finding, returning it and whether it is new.

    A finding that already exists keeps its identity and its first_seen. What
    the detector says about it now replaces what it said before, because the
    detector is the authority on its own conclusion.
    """
    finding = session.scalar(
        select(Finding).where(
            Finding.dockyard_id == dockyard_id, Finding.fingerprint == fingerprint
        )
    )
    created = finding is None
    if finding is None:
        finding = Finding(
            dockyard_id=dockyard_id,
            fingerprint=fingerprint,
            first_seen=seen_at,
            first_detection_run_id=detection_run_id,
            status=str(FindingStatus.OPEN),
        )
        session.add(finding)
    elif finding.status == str(FindingStatus.RESOLVED):
        # It is back. Reopening keeps one history for one issue instead of
        # starting a second record that looks unrelated to the first.
        finding.status = str(FindingStatus.OPEN)
        finding.resolved_at = None

    finding.detector = detector_id
    finding.detector_version = detector_version
    finding.rule_id = detected.rule_id
    finding.title = detected.title[:200]
    finding.description = detected.description
    finding.category = str(detected.category)
    finding.severity = str(detected.severity)
    finding.confidence = str(detected.confidence)
    finding.asset_id = detected.asset_id
    finding.service_id = detected.service_id
    finding.remediation = detected.remediation
    finding.detail = dict(detected.detail)
    finding.cve_references = [reference.document() for reference in detected.cve_references] or None
    finding.last_seen = seen_at
    finding.last_detection_run_id = detection_run_id
    session.flush()
    return finding, created


def attach_evidence(
    session: Session,
    *,
    finding: Finding,
    detection_run_id: int,
    observations: dict[int, Observation],
    observation_ids: tuple[int, ...],
) -> int:
    """Link a finding to the observations that support it.

    Observations are immutable, so re-running detection over unchanged data adds
    nothing here; new links appear only when new discovery produced new
    observations.
    """
    existing = {
        row.observation_id
        for row in session.scalars(
            select(FindingEvidence).where(FindingEvidence.finding_id == finding.id)
        )
    }
    added = 0
    for observation_id in observation_ids:
        observation = observations.get(observation_id)
        if observation is None or observation_id in existing:
            continue
        session.add(
            FindingEvidence(
                finding_id=finding.id,
                observation_id=observation.id,
                detection_run_id=detection_run_id,
                discovery_run_id=observation.discovery_run_id,
                evidence_record_id=_normalized_record_id(session, observation.discovery_run_id),
                summary=observation.summary[:500],
            )
        )
        existing.add(observation_id)
        added += 1
    session.flush()
    return added


def resolve_absent(
    session: Session,
    *,
    dockyard_id: int,
    detector_id: str,
    reproduced: set[str],
    resolved_at: datetime,
) -> list[Finding]:
    """Resolve the open findings this detector no longer reproduces.

    Only findings from the detector that just ran successfully are considered:
    a detector that failed must not be able to resolve anything by not running.
    Findings an operator suppressed or accepted are left alone, because that
    status is their decision and not an observation about the data.
    """
    candidates = session.scalars(
        select(Finding).where(
            Finding.dockyard_id == dockyard_id,
            Finding.detector == detector_id,
            Finding.status.not_in([str(status) for status in OPERATOR_OWNED_STATUSES]),
        )
    )
    resolved = []
    for finding in candidates:
        if finding.fingerprint in reproduced or finding.status == str(FindingStatus.RESOLVED):
            continue
        finding.status = str(FindingStatus.RESOLVED)
        finding.resolved_at = resolved_at
        resolved.append(finding)
    session.flush()
    return resolved


def findings_query(
    dockyard_id: int,
    *,
    status: str | None = None,
    severity: str | None = None,
    detector: str | None = None,
    asset_id: int | None = None,
    service_id: int | None = None,
) -> Select[tuple[Finding]]:
    """The one place a findings filter is built, so isolation is not optional."""
    statement = select(Finding).where(Finding.dockyard_id == dockyard_id)
    if status is not None:
        statement = statement.where(Finding.status == status)
    if severity is not None:
        statement = statement.where(Finding.severity == severity)
    if detector is not None:
        statement = statement.where(Finding.detector == detector)
    if asset_id is not None:
        statement = statement.where(Finding.asset_id == asset_id)
    if service_id is not None:
        statement = statement.where(Finding.service_id == service_id)
    return statement.order_by(
        case(_SEVERITY_ORDER, value=Finding.severity, else_=len(_SEVERITY_ORDER)),
        Finding.last_seen.desc(),
        Finding.id.desc(),
    )


def list_findings(session: Session, dockyard_id: int, limit: int, **filters) -> list[Finding]:
    return list(session.scalars(findings_query(dockyard_id, **filters).limit(limit)))


def get_finding(session: Session, dockyard_id: int, finding_id: int) -> Finding | None:
    return session.scalar(
        select(Finding).where(Finding.dockyard_id == dockyard_id, Finding.id == finding_id)
    )


def open_finding_count(session: Session, dockyard_id: int) -> int:
    statement = (
        select(func.count())
        .select_from(Finding)
        .where(Finding.dockyard_id == dockyard_id, Finding.status == str(FindingStatus.OPEN))
    )
    return session.scalar(statement) or 0


def set_status(
    session: Session, finding: Finding, status: FindingStatus, note: str | None
) -> Finding:
    """Apply an operator decision.

    Reopening clears `resolved_at`, because a finding that is open was not
    resolved. Suppressing or accepting does not clear it: that history stays.
    """
    finding.status = str(status)
    finding.status_note = note
    if status is FindingStatus.OPEN:
        finding.resolved_at = None
    session.commit()
    session.refresh(finding)
    return finding


def list_evidence(session: Session, finding_id: int) -> list[FindingEvidence]:
    return list(
        session.scalars(
            select(FindingEvidence)
            .where(FindingEvidence.finding_id == finding_id)
            .order_by(FindingEvidence.id)
        )
    )


def _normalized_record_id(session: Session, discovery_run_id: int | None) -> int | None:
    """The hashed normalized result an observation came from, when there is one."""
    if discovery_run_id is None:
        return None
    return session.scalar(
        select(EvidenceRecord.id)
        .where(
            EvidenceRecord.discovery_run_id == discovery_run_id,
            EvidenceRecord.kind == "normalized",
        )
        .order_by(EvidenceRecord.id)
        .limit(1)
    )
