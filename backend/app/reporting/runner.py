"""Build immutable reports from retained RedDock state and evidence only.

Reporting has no target, socket, subprocess, model, prompt, or operator-selected
path. A DockPack contains only database-referenced artifacts whose bytes still
match their retained SHA-256 values. All output is canonical and ZIP metadata is
fixed, so unchanged Dockyard state produces byte-identical exports.
"""

import json
import logging
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO
from pathlib import Path, PurePosixPath
from threading import Lock
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.evidence import (
    METADATA_FILE,
    NORMALIZED_FILE,
    REPORTING_SCOPE,
    EvidenceError,
    EvidenceStore,
)
from app.models import (
    Asset,
    CorrelationRun,
    DetectionRun,
    DiscoveryRun,
    Dockyard,
    EvidenceRecord,
    Finding,
    FindingEvidence,
    IntelligenceRun,
    Observation,
    ReportRun,
    ScopeEntry,
    Service,
    ValidationRun,
)

REPORT_SCHEMA = "reddock.reporting/1"
MANIFEST_SCHEMA = "reddock.evidence-manifest/1"
DOCKPACK_SCHEMA = "reddock.dockpack/1"
ACTIVE_STATUSES = ("pending", "queued", "running")
_CREATE_LOCK = Lock()
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
logger = logging.getLogger("reddock.reporting")


class ReportRejected(RuntimeError):
    """Raised when a trustworthy, bounded report cannot be produced."""


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    source: str
    run_id: int
    source_path: str
    archive_path: str
    media_type: str
    expected_sha256: str
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class VerifiedArtifact:
    reference: ArtifactReference
    payload: bytes

    @property
    def sha256(self) -> str:
        return self.reference.expected_sha256


def start_report(session: Session, dockyard_id: int) -> ReportRun:
    """Create one complete reporting snapshot under the single-process lock."""
    with _CREATE_LOCK:
        return _start_report(session, dockyard_id)


def _start_report(session: Session, dockyard_id: int) -> ReportRun:
    settings = get_settings()
    count = (
        session.scalar(
            select(func.count()).select_from(ReportRun).where(ReportRun.dockyard_id == dockyard_id)
        )
        or 0
    )
    if count >= settings.max_report_runs_per_dockyard:
        raise ReportRejected("This Dockyard reached the fixed report-run limit")
    session.rollback()
    _reject_active_sources(session, dockyard_id)
    try:
        references = _artifact_references(session, dockyard_id)
    except OSError as error:
        raise ReportRejected("A retained evidence path is unavailable") from error
    if not references:
        raise ReportRejected("No retained evidence is available to report")

    run = ReportRun(dockyard_id=dockyard_id, status="running", report_schema=REPORT_SCHEMA)
    session.add(run)
    session.commit()
    session.refresh(run)

    # sqlite3's legacy transaction mode does not begin a read transaction for
    # SELECT statements. Start one explicitly so every source query observes
    # one immutable database state and concurrent mutations wait until it is
    # captured. BEGIN IMMEDIATE is intentionally SQLite-specific; other engines
    # already have a real transaction after session.connection().
    session.rollback()
    connection = session.connection()
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN IMMEDIATE")
    store = EvidenceStore()
    try:
        _reject_active_sources(session, dockyard_id)
        references = _artifact_references(session, dockyard_id)
        if not references:
            raise ReportRejected("No retained evidence is available to report")
        verified = _verify_artifacts(store.root, references)
        manifest = _evidence_manifest(verified)
        snapshot = _snapshot(session, dockyard_id, manifest)
        _enrich_manifest(manifest, snapshot)
        session.commit()
        session.refresh(run)

        snapshot_bytes = _document(snapshot)
        technical = _technical_markdown(snapshot).encode()
        executive = _executive_markdown(snapshot).encode()
        manifest_bytes = _document(manifest)
        package = _dockpack(snapshot_bytes, technical, executive, manifest_bytes, verified)
        if len(package) > settings.max_dockpack_bytes:
            raise ReportRejected("DockPack exceeds the fixed export size limit")
        for payload, label in (
            (snapshot_bytes, "technical report"),
            (technical, "technical report"),
            (executive, "executive report"),
            (manifest_bytes, "evidence manifest"),
        ):
            if len(payload) > settings.max_dockpack_bytes:
                raise ReportRejected(f"The {label} exceeds the fixed export size limit")

        normalized = store.write_normalized(dockyard_id, run.id, snapshot, scope=REPORTING_SCOPE)
        technical_file = store.write_export(
            dockyard_id,
            run.id,
            "technical.md",
            "text/markdown; charset=utf-8",
            technical,
        )
        executive_file = store.write_export(
            dockyard_id,
            run.id,
            "executive.md",
            "text/markdown; charset=utf-8",
            executive,
        )
        manifest_file = store.write_export(
            dockyard_id,
            run.id,
            "evidence-manifest.json",
            "application/json",
            manifest_bytes,
        )
        dockpack = store.write_export(
            dockyard_id,
            run.id,
            "dockpack.zip",
            "application/zip",
            package,
        )
        run.snapshot_sha256 = normalized.sha256
        run.technical_sha256 = technical_file.sha256
        run.executive_sha256 = executive_file.sha256
        run.manifest_sha256 = manifest_file.sha256
        run.dockpack_sha256 = dockpack.sha256
        run.dockpack_bytes = dockpack.size_bytes
        run.evidence_path = store.relative_run_path(dockyard_id, run.id, REPORTING_SCOPE)
        run.source_counts = snapshot["counts"]
        run.status = "completed"
        run.completed_at = datetime.now(UTC)
        session.commit()
        session.refresh(run)
        return run
    except (EvidenceError, ReportRejected, OSError, ValueError, json.JSONDecodeError) as error:
        session.rollback()
        _remove_partial_report(store, dockyard_id, run.id)
        failed = session.get(ReportRun, run.id)
        if failed is None:
            raise ReportRejected(str(error)) from error
        failed.status = "failed"
        failed.error = str(error)[:500]
        failed.completed_at = datetime.now(UTC)
        session.commit()
        session.refresh(failed)
        return failed
    except Exception:
        logger.exception("Report run %s failed unexpectedly", run.id)
        session.rollback()
        _remove_partial_report(store, dockyard_id, run.id)
        failed = session.get(ReportRun, run.id)
        if failed is None:
            raise
        failed.status = "failed"
        failed.error = "Reporting failed unexpectedly; see the RedDock container log"
        failed.completed_at = datetime.now(UTC)
        session.commit()
        session.refresh(failed)
        return failed


def list_runs(session: Session, dockyard_id: int, limit: int) -> list[ReportRun]:
    return list(
        session.scalars(
            select(ReportRun)
            .where(ReportRun.dockyard_id == dockyard_id)
            .order_by(ReportRun.id.desc())
            .limit(limit)
        )
    )


def get_run(session: Session, dockyard_id: int, run_id: int) -> ReportRun | None:
    return session.scalar(
        select(ReportRun).where(ReportRun.dockyard_id == dockyard_id, ReportRun.id == run_id)
    )


def artifact_path(run: ReportRun, artifact: str) -> Path:
    """Return a completed report artifact only after rechecking its digest."""
    choices = {
        "technical": ("raw/technical.md", run.technical_sha256),
        "executive": ("raw/executive.md", run.executive_sha256),
        "manifest": ("raw/evidence-manifest.json", run.manifest_sha256),
        "dockpack": ("raw/dockpack.zip", run.dockpack_sha256),
    }
    if run.status != "completed" or artifact not in choices or not run.evidence_path:
        raise ReportRejected("Report artifact is not available")
    relative, expected = choices[artifact]
    if not expected:
        raise ReportRejected("Report artifact is not available")
    path = _safe_file(EvidenceStore().root, f"{run.evidence_path}/{relative}")
    payload = _read_bounded(
        path,
        get_settings().max_dockpack_bytes,
        "Report artifact exceeds the fixed download size limit",
    )
    if sha256(payload).hexdigest() != expected:
        raise ReportRejected("Report artifact no longer matches its retained SHA-256")
    return path


def recover_interrupted_runs(session: Session) -> int:
    rows = list(session.scalars(select(ReportRun).where(ReportRun.status == "running")))
    store = EvidenceStore()
    for run in rows:
        _remove_partial_report(store, run.dockyard_id, run.id)
        run.status = "failed"
        run.error = "Reporting was interrupted by an application restart"
        run.completed_at = datetime.now(UTC)
    if rows:
        session.commit()
    return len(rows)


def _reject_active_sources(session: Session, dockyard_id: int) -> None:
    models = (DiscoveryRun, DetectionRun, ValidationRun, CorrelationRun, IntelligenceRun)
    for model in models:
        active = (
            session.scalar(
                select(func.count())
                .select_from(model)
                .where(model.dockyard_id == dockyard_id, model.status.in_(ACTIVE_STATUSES))
            )
            or 0
        )
        if active:
            raise ReportRejected("Wait for active Dockyard runs to finish before reporting")


def _artifact_references(session: Session, dockyard_id: int) -> list[ArtifactReference]:
    references: list[ArtifactReference] = []
    records = session.scalars(
        select(EvidenceRecord)
        .where(EvidenceRecord.dockyard_id == dockyard_id)
        .order_by(EvidenceRecord.discovery_run_id, EvidenceRecord.relative_path, EvidenceRecord.id)
    )
    for record in records:
        _add_references(
            references,
            _reference(
                "discovery",
                record.discovery_run_id,
                f"{dockyard_id}/{record.discovery_run_id}/{record.relative_path}",
                f"evidence/discovery/{record.discovery_run_id}/{record.relative_path}",
                record.media_type,
                record.sha256,
                record.truncated,
            ),
        )

    detections = session.scalars(
        select(DetectionRun)
        .where(
            DetectionRun.dockyard_id == dockyard_id,
            DetectionRun.status == "completed",
            DetectionRun.evidence_path.is_not(None),
        )
        .order_by(DetectionRun.id)
    )
    for run in detections:
        _known_pair(references, "detection", run.id, run.evidence_path, run)

    validations = session.scalars(
        select(ValidationRun)
        .where(
            ValidationRun.dockyard_id == dockyard_id,
            ValidationRun.status == "completed",
            ValidationRun.evidence_path.is_not(None),
        )
        .order_by(ValidationRun.id)
    )
    for run in validations:
        _known_pair(references, "validation", run.id, run.evidence_path, run)
        if run.manifest_sha256:
            _add_references(
                references,
                _reference(
                    "validation",
                    run.id,
                    f"{run.evidence_path}/raw/manifest.json",
                    f"evidence/validation/{run.id}/raw/manifest.json",
                    "application/json",
                    run.manifest_sha256,
                ),
            )
            manifest_path = _safe_file(
                EvidenceStore().root, f"{run.evidence_path}/raw/manifest.json"
            )
            manifest_payload = _read_bounded(
                manifest_path,
                get_settings().max_evidence_bytes,
                "Validation manifest exceeds the fixed evidence size limit",
            )
            if sha256(manifest_payload).hexdigest() != run.manifest_sha256:
                raise ReportRejected("Validation manifest no longer matches its retained SHA-256")
            for artifact in _validation_manifest_entries(manifest_payload):
                _add_references(
                    references,
                    _reference(
                        "validation",
                        run.id,
                        f"{run.evidence_path}/{artifact['path']}",
                        f"evidence/validation/{run.id}/{artifact['path']}",
                        str(artifact["media_type"]),
                        str(artifact["sha256"]),
                        bool(artifact.get("truncated", False)),
                    ),
                )

    correlations = session.scalars(
        select(CorrelationRun)
        .where(
            CorrelationRun.dockyard_id == dockyard_id,
            CorrelationRun.status == "completed",
            CorrelationRun.evidence_path.is_not(None),
        )
        .order_by(CorrelationRun.id)
    )
    for run in correlations:
        _known_pair(references, "correlation", run.id, run.evidence_path, run)

    intelligence = session.scalars(
        select(IntelligenceRun)
        .where(
            IntelligenceRun.dockyard_id == dockyard_id,
            IntelligenceRun.evidence_path.is_not(None),
            IntelligenceRun.status != "running",
        )
        .order_by(IntelligenceRun.id)
    )
    for run in intelligence:
        if run.input_sha256:
            _add_references(
                references,
                _reference(
                    "intelligence",
                    run.id,
                    f"{run.evidence_path}/{NORMALIZED_FILE}",
                    f"evidence/intelligence/{run.id}/{NORMALIZED_FILE}",
                    "application/json",
                    run.input_sha256,
                ),
            )
        if run.status == "completed" and run.result_sha256 and run.metadata_sha256:
            _add_references(
                references,
                _reference(
                    "intelligence",
                    run.id,
                    f"{run.evidence_path}/raw/advice.json",
                    f"evidence/intelligence/{run.id}/raw/advice.json",
                    "application/json",
                    run.result_sha256,
                ),
                _reference(
                    "intelligence",
                    run.id,
                    f"{run.evidence_path}/{METADATA_FILE}",
                    f"evidence/intelligence/{run.id}/{METADATA_FILE}",
                    "application/json",
                    run.metadata_sha256,
                ),
            )
    return _deduplicate(references)


def _validation_manifest_entries(payload: bytes) -> list[dict]:
    try:
        manifest = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ReportRejected("Validation manifest is not valid JSON") from error
    if not isinstance(manifest, dict) or manifest.get("schema") != "reddock.validation-package/1":
        raise ReportRejected("Validation manifest has an unsupported schema")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) > 4:
        raise ReportRejected("Validation manifest has an invalid artifact list")
    raw = [
        item
        for item in artifacts
        if isinstance(item, dict) and item.get("path") == "raw/http-recheck.json"
    ]
    if len(raw) != 1:
        raise ReportRejected("Validation manifest does not name exactly one raw recheck artifact")
    item = raw[0]
    required = ("media_type", "sha256")
    if any(not isinstance(item.get(field), str) for field in required):
        raise ReportRejected("Validation manifest has an invalid raw artifact entry")
    return raw


def _known_pair(
    target: list[ArtifactReference], source: str, run_id: int, base: str | None, run
) -> None:
    if not base or not run.result_sha256 or not run.metadata_sha256:
        raise ReportRejected(f"Completed {source} run #{run_id} has incomplete evidence hashes")
    _add_references(
        target,
        _reference(
            source,
            run_id,
            f"{base}/{NORMALIZED_FILE}",
            f"evidence/{source}/{run_id}/{NORMALIZED_FILE}",
            "application/json",
            run.result_sha256,
        ),
        _reference(
            source,
            run_id,
            f"{base}/{METADATA_FILE}",
            f"evidence/{source}/{run_id}/{METADATA_FILE}",
            "application/json",
            run.metadata_sha256,
        ),
    )


def _add_references(target: list[ArtifactReference], *items: ArtifactReference) -> None:
    if len(target) + len(items) > get_settings().max_report_evidence_files:
        raise ReportRejected("The evidence manifest exceeds the fixed file-count limit")
    target.extend(items)


def _reference(
    source: str,
    run_id: int,
    source_path: str,
    archive_path: str,
    media_type: str,
    expected_sha256: str,
    truncated: bool = False,
) -> ArtifactReference:
    if len(expected_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in expected_sha256
    ):
        raise ReportRejected("A retained evidence reference has an invalid SHA-256")
    _safe_relative(source_path)
    _safe_relative(archive_path)
    return ArtifactReference(
        source, int(run_id), source_path, archive_path, media_type, expected_sha256, truncated
    )


def _deduplicate(references: list[ArtifactReference]) -> list[ArtifactReference]:
    unique: dict[str, ArtifactReference] = {}
    for reference in references:
        if reference.archive_path in unique:
            raise ReportRejected("Duplicate retained evidence references share one export path")
        unique[reference.archive_path] = reference
    return [unique[path] for path in sorted(unique)]


def _verify_artifacts(root: Path, references: list[ArtifactReference]) -> list[VerifiedArtifact]:
    settings = get_settings()
    if len(references) > settings.max_report_evidence_files:
        raise ReportRejected("The evidence manifest exceeds the fixed file-count limit")
    verified: list[VerifiedArtifact] = []
    total = 0
    for reference in references:
        path = _safe_file(root, reference.source_path)
        payload = _read_bounded(
            path,
            settings.max_dockpack_bytes - total,
            "Retained evidence exceeds the fixed DockPack size limit",
        )
        total += len(payload)
        if sha256(payload).hexdigest() != reference.expected_sha256:
            raise ReportRejected(
                f"Retained evidence no longer matches its SHA-256: {reference.source_path}"
            )
        verified.append(VerifiedArtifact(reference, payload))
    return verified


def _evidence_manifest(artifacts: list[VerifiedArtifact]) -> dict:
    return {
        "schema": MANIFEST_SCHEMA,
        "algorithm": "sha256",
        "files": [
            {
                "source": artifact.reference.source,
                "run_id": artifact.reference.run_id,
                "source_path": artifact.reference.source_path,
                "archive_path": artifact.reference.archive_path,
                "media_type": artifact.reference.media_type,
                "bytes": len(artifact.payload),
                "sha256": artifact.sha256,
                "truncated": artifact.reference.truncated,
            }
            for artifact in artifacts
        ],
        "file_count": len(artifacts),
        "total_bytes": sum(len(artifact.payload) for artifact in artifacts),
    }


def _enrich_manifest(manifest: dict, snapshot: dict) -> None:
    """Bind the file inventory to the Dockyard scope and finding claims it supports."""
    available_hashes = {item["sha256"] for item in manifest["files"]}
    claims = []
    for finding in snapshot["findings"]:
        evidence = finding["evidence"]
        if not evidence:
            raise ReportRejected(f"Finding #{finding['id']} has no retained evidence")
        if any(item["sha256"] not in available_hashes for item in evidence):
            raise ReportRejected(f"Finding #{finding['id']} cites evidence absent from the pack")
        claims.append(
            {
                "id": finding["id"],
                "fingerprint": finding["fingerprint"],
                "detector": finding["detector"],
                "rule_id": finding["rule_id"],
                "status": finding["status"],
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "evidence": [
                    {
                        "observation_id": item["observation_id"],
                        "discovery_run_id": item["discovery_run_id"],
                        "detection_run_id": item["detection_run_id"],
                        "sha256": item["sha256"],
                    }
                    for item in evidence
                ],
            }
        )
    run_ids: dict[str, list[int]] = {}
    for item in manifest["files"]:
        run_ids.setdefault(item["source"], []).append(item["run_id"])
    manifest.update(
        {
            "dockyard_id": snapshot["dockyard"]["id"],
            "generator": snapshot["generator"],
            "scope_sha256": sha256(_document({"scope": snapshot["scope"]})).hexdigest(),
            "cited_run_ids": {source: sorted(set(ids)) for source, ids in sorted(run_ids.items())},
            "findings": claims,
            "skipped_findings": [],
        }
    )


def _snapshot(session: Session, dockyard_id: int, manifest: dict) -> dict:
    settings = get_settings()
    dockyard = session.get(Dockyard, dockyard_id)
    if dockyard is None:
        raise ReportRejected("Dockyard not found")
    assets = list(
        session.scalars(
            select(Asset)
            .where(Asset.dockyard_id == dockyard_id)
            .order_by(Asset.id)
            .limit(settings.max_report_assets + 1)
        )
    )
    _reject_oversized_collection(assets, settings.max_report_assets, "asset")
    services = list(
        session.scalars(
            select(Service)
            .join(Asset, Asset.id == Service.asset_id)
            .where(Asset.dockyard_id == dockyard_id)
            .order_by(Service.asset_id, Service.transport, Service.port, Service.id)
            .limit(settings.max_report_services + 1)
        )
    )
    _reject_oversized_collection(services, settings.max_report_services, "service")
    findings = list(
        session.scalars(
            select(Finding)
            .where(Finding.dockyard_id == dockyard_id)
            .order_by(Finding.id)
            .limit(settings.max_report_findings + 1)
        )
    )
    _reject_oversized_collection(findings, settings.max_report_findings, "finding")
    evidence = _finding_evidence(session, dockyard_id)
    validations = _validation_rows(session, dockyard_id)
    correlation = session.scalar(
        select(CorrelationRun)
        .where(CorrelationRun.dockyard_id == dockyard_id, CorrelationRun.status == "completed")
        .order_by(CorrelationRun.id.desc())
        .limit(1)
    )
    intelligence = session.scalar(
        select(IntelligenceRun)
        .where(IntelligenceRun.dockyard_id == dockyard_id, IntelligenceRun.status == "completed")
        .order_by(IntelligenceRun.id.desc())
        .limit(1)
    )
    scopes = list(
        session.scalars(
            select(ScopeEntry)
            .where(ScopeEntry.dockyard_id == dockyard_id)
            .order_by(ScopeEntry.id)
            .limit(settings.max_scope_entries + 1)
        )
    )
    _reject_oversized_collection(scopes, settings.max_scope_entries, "scope-entry")
    severity = {name: 0 for name in ("critical", "high", "medium", "low", "informational")}
    status = {name: 0 for name in ("open", "accepted", "resolved", "suppressed")}
    for finding in findings:
        severity[finding.severity] = severity.get(finding.severity, 0) + 1
        status[finding.status] = status.get(finding.status, 0) + 1
    counts = {
        "assets": len(assets),
        "services": len(services),
        "observations": session.scalar(
            select(func.count())
            .select_from(Observation)
            .where(Observation.dockyard_id == dockyard_id)
        )
        or 0,
        "findings": len(findings),
        "findings_by_severity": severity,
        "findings_by_status": status,
        "validations": sum(len(rows) for rows in validations.values()),
        "evidence_files": manifest["file_count"],
        "evidence_bytes": manifest["total_bytes"],
    }
    return {
        "schema": REPORT_SCHEMA,
        "generator": {"name": settings.app_name, "version": settings.version},
        "basis": "retained RedDock state and SHA-256-verified evidence only",
        "dockyard": {
            "id": dockyard.id,
            "name": dockyard.name,
            "description": dockyard.description,
            "status": dockyard.status,
        },
        "scope": [
            {"rule": row.rule, "kind": row.kind, "value": row.value, "note": row.note}
            for row in scopes
        ],
        "counts": counts,
        "assets": [
            {
                "id": row.id,
                "type": row.asset_type,
                "identity": row.identity,
                "display_name": row.display_name,
                "ip_address": row.ip_address,
                "hostname": row.hostname,
                "first_seen": _iso(row.first_seen),
                "last_seen": _iso(row.last_seen),
            }
            for row in assets
        ],
        "services": [
            {
                "id": row.id,
                "asset_id": row.asset_id,
                "transport": row.transport,
                "port": row.port,
                "state": row.state,
                "service_name": row.service_name,
                "product": row.product,
                "version": row.version,
                "first_seen": _iso(row.first_seen),
                "last_seen": _iso(row.last_seen),
            }
            for row in services
        ],
        "findings": [
            {
                "id": row.id,
                "fingerprint": row.fingerprint,
                "detector": row.detector,
                "detector_version": row.detector_version,
                "rule_id": row.rule_id,
                "title": row.title,
                "description": row.description,
                "category": row.category,
                "severity": row.severity,
                "confidence": row.confidence,
                "status": row.status,
                "status_note": row.status_note,
                "asset_id": row.asset_id,
                "service_id": row.service_id,
                "remediation": row.remediation,
                "cve_references": row.cve_references or [],
                "first_seen": _iso(row.first_seen),
                "last_seen": _iso(row.last_seen),
                "resolved_at": _iso(row.resolved_at),
                "evidence": evidence.get(row.id, []),
                "validations": validations.get(row.id, []),
            }
            for row in findings
        ],
        "correlation": _correlation_snapshot(correlation),
        "intelligence": _intelligence_snapshot(intelligence),
        "evidence_manifest": manifest,
        "limitations": [
            "This report describes retained observations and detector conclusions; it is not "
            "proof of exploitability.",
            "Severity and confidence are separate. RedDock computes no aggregate risk score "
            "or CVSS value.",
            "Resolved, accepted, and suppressed findings remain in the snapshot for auditability.",
            "Model output, when present, is advice only and cannot modify RedDock state.",
        ],
    }


def _finding_evidence(session: Session, dockyard_id: int) -> dict[int, list[dict]]:
    limit = get_settings().max_report_evidence_links
    rows = session.execute(
        select(FindingEvidence, EvidenceRecord)
        .join(Finding, Finding.id == FindingEvidence.finding_id)
        .outerjoin(EvidenceRecord, EvidenceRecord.id == FindingEvidence.evidence_record_id)
        .where(Finding.dockyard_id == dockyard_id)
        .order_by(FindingEvidence.finding_id, FindingEvidence.id)
        .limit(limit + 1)
    )
    result: dict[int, list[dict]] = {}
    for index, (link, record) in enumerate(rows, start=1):
        if index > limit:
            raise ReportRejected("The report exceeds the fixed finding-evidence limit")
        if record is None:
            raise ReportRejected(f"Finding #{link.finding_id} has an unavailable evidence record")
        result.setdefault(link.finding_id, []).append(
            {
                "observation_id": link.observation_id,
                "discovery_run_id": link.discovery_run_id,
                "detection_run_id": link.detection_run_id,
                "summary": link.summary,
                "path": (f"{dockyard_id}/{record.discovery_run_id}/{record.relative_path}"),
                "sha256": record.sha256,
            }
        )
    return result


def _validation_rows(session: Session, dockyard_id: int) -> dict[int, list[dict]]:
    limit = get_settings().max_validation_runs_per_dockyard
    rows = session.scalars(
        select(ValidationRun)
        .where(ValidationRun.dockyard_id == dockyard_id)
        .order_by(ValidationRun.finding_id, ValidationRun.id)
        .limit(limit + 1)
    )
    result: dict[int, list[dict]] = {}
    for index, row in enumerate(rows, start=1):
        if index > limit:
            raise ReportRejected("The report exceeds the fixed validation-row limit")
        result.setdefault(row.finding_id, []).append(
            {
                "id": row.id,
                "status": row.status,
                "outcome": row.outcome,
                "confidence": row.confidence,
                "summary": row.summary,
                "decision": row.decision,
                "result_sha256": row.result_sha256,
                "manifest_sha256": row.manifest_sha256,
                "completed_at": _iso(row.completed_at),
            }
        )
    return result


def _correlation_snapshot(run: CorrelationRun | None) -> dict | None:
    if run is None:
        return None
    return {
        "run_id": run.id,
        "result_sha256": run.result_sha256,
        "graph": run.graph,
        "completed_at": _iso(run.completed_at),
    }


def _intelligence_snapshot(run: IntelligenceRun | None) -> dict | None:
    if run is None:
        return None
    return {
        "run_id": run.id,
        "provider": run.provider,
        "model": run.model,
        "destination": run.destination,
        "sends_data_external": run.sends_data_external,
        "prompt_version": run.prompt_version,
        "approval_note": run.approval_note,
        "input_sha256": run.input_sha256,
        "result_sha256": run.result_sha256,
        "output": run.output,
        "completed_at": _iso(run.completed_at),
    }


def _technical_markdown(snapshot: dict) -> str:
    dockyard = snapshot["dockyard"]
    counts = snapshot["counts"]
    lines = [
        f"# RedDock technical report — {_md(dockyard['name'])}",
        "",
        f"Report schema: `{REPORT_SCHEMA}`  ",
        f"Generator: `RedDock {snapshot['generator']['version']}`  ",
        f"Basis: {_md(snapshot['basis'])}",
        "",
        "## Scope",
        "",
    ]
    if snapshot["scope"]:
        lines.extend(["| Rule | Kind | Value | Note |", "| --- | --- | --- | --- |"])
        for row in snapshot["scope"]:
            lines.append(
                f"| {_md(row['rule'])} | {_md(row['kind'])} | {_md(row['value'])} | "
                f"{_md(row['note'])} |"
            )
    else:
        lines.append("No scope entries were retained in this Dockyard.")
    lines.extend(
        [
            "",
            "## Inventory summary",
            "",
            f"- Assets: {counts['assets']}",
            f"- Services: {counts['services']}",
            f"- Observations: {counts['observations']}",
            f"- Findings: {counts['findings']}",
            f"- Validation requests: {counts['validations']}",
            f"- Verified evidence files: {counts['evidence_files']}",
            "",
            "## Assets and services",
            "",
        ]
    )
    services = {}
    for service in snapshot["services"]:
        services.setdefault(service["asset_id"], []).append(service)
    for asset in snapshot["assets"]:
        lines.extend(
            [
                f"### Asset #{asset['id']} — {_md(asset['display_name'])}",
                "",
                f"Type: `{_md_code(asset['type'])}`  ",
                f"Identity: `{_md_code(asset['identity'])}`  ",
                f"First seen: `{_md_code(asset['first_seen'])}`  ",
                f"Last seen: `{_md_code(asset['last_seen'])}`",
                "",
            ]
        )
        for service in services.get(asset["id"], []):
            label = service["service_name"] or "unidentified"
            product = " ".join(item for item in (service["product"], service["version"]) if item)
            lines.append(
                f"- `{_md_code(service['transport'])}/{service['port']}` — {_md(label)}"
                + (f"; target reported {_md(product)}" if product else "")
            )
        if not services.get(asset["id"]):
            lines.append("- No retained services.")
        lines.append("")
    lines.extend(["## Findings", ""])
    if not snapshot["findings"]:
        lines.extend(["No detector findings were retained.", ""])
    for finding in snapshot["findings"]:
        lines.extend(
            [
                f"### Finding #{finding['id']} — {_md(finding['title'])}",
                "",
                f"- Rule: `{_md_code(finding['detector'])}/{_md_code(finding['rule_id'])}`",
                f"- Status: `{_md_code(finding['status'])}`",
                f"- Severity: `{_md_code(finding['severity'])}`",
                f"- Confidence: `{_md_code(finding['confidence'])}`",
                f"- Subject: asset `{_md_code(finding['asset_id'])}`, "
                f"service `{_md_code(finding['service_id'])}`",
                "",
                _md(finding["description"]),
                "",
                f"Remediation: {_md(finding['remediation'])}",
                "",
                "Evidence:",
            ]
        )
        for evidence in finding["evidence"]:
            lines.append(
                f"- Observation #{evidence['observation_id']}: `{evidence['sha256']}` — "
                f"{_md(evidence['summary'])}"
            )
        for validation in finding["validations"]:
            lines.append(
                f"- Validation #{validation['id']}: `{_md_code(validation['status'])}`"
                f" / `{_md_code(validation['outcome'])}` — {_md(validation['summary'])}"
            )
        lines.append("")
    lines.extend(["## Correlation and non-authoritative intelligence", ""])
    correlation = snapshot["correlation"]
    intelligence = snapshot["intelligence"]
    lines.append(
        f"- Latest completed correlation: `{correlation['result_sha256']}`"
        if correlation
        else "- No completed correlation snapshot."
    )
    if intelligence:
        lines.extend(
            [
                "- Latest completed intelligence is non-authoritative advice only.",
                f"- Provider: `{_md_code(intelligence['provider'])}` / "
                f"`{_md_code(intelligence['model'])}`",
                f"- Reviewed packet SHA-256: `{intelligence['input_sha256']}`",
                f"- Advice SHA-256: `{intelligence['result_sha256']}`",
                f"- Approval note: {_md(intelligence['approval_note'])}",
            ]
        )
    else:
        lines.append("- No completed intelligence advice.")
    lines.extend(["", "## Evidence manifest", ""])
    for item in snapshot["evidence_manifest"]["files"]:
        lines.append(
            f"- `{item['sha256']}`  `{_md_code(item['archive_path'])}` ({item['bytes']} bytes)"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {_md(item)}" for item in snapshot["limitations"])
    return "\n".join(lines).rstrip() + "\n"


def _executive_markdown(snapshot: dict) -> str:
    dockyard = snapshot["dockyard"]
    counts = snapshot["counts"]
    severity = counts["findings_by_severity"]
    status = counts["findings_by_status"]
    open_items = status.get("open", 0)
    validated = sum(
        1
        for finding in snapshot["findings"]
        for validation in finding["validations"]
        if validation["status"] == "completed"
    )
    lines = [
        f"# RedDock executive report — {_md(dockyard['name'])}",
        "",
        "## Assessment snapshot",
        "",
        (
            f"RedDock retained {counts['assets']} assets, {counts['services']} services, "
            f"and {counts['observations']} observations in this authorized Dockyard. "
            f"Detectors produced {counts['findings']} evidence-linked findings; "
            f"{open_items} are currently open."
        ),
        "",
        "## Finding posture",
        "",
        f"- Critical: {severity.get('critical', 0)}",
        f"- High: {severity.get('high', 0)}",
        f"- Medium: {severity.get('medium', 0)}",
        f"- Low: {severity.get('low', 0)}",
        f"- Informational: {severity.get('informational', 0)}",
        f"- Accepted: {status.get('accepted', 0)}",
        f"- Resolved: {status.get('resolved', 0)}",
        f"- Suppressed: {status.get('suppressed', 0)}",
        f"- Completed validation rechecks: {validated}",
        "",
        "## Evidence assurance",
        "",
        (
            f"This snapshot includes {counts['evidence_files']} retained artifacts "
            f"({counts['evidence_bytes']} bytes). Every included artifact was re-read and "
            "matched to its stored SHA-256 before the DockPack was created."
        ),
        "",
        "## Interpretation",
        "",
        (
            "Findings are detector conclusions grounded in retained observations. They do not "
            "state that RedDock exploited a target. Severity describes potential importance; "
            "confidence describes evidentiary certainty. RedDock does not calculate an "
            "aggregate risk score."
        ),
        "",
        "## Recommended handling",
        "",
        (
            "Review open findings alongside their technical evidence and validation outcomes. "
            "Track accepted, resolved, and suppressed items as part of the audit trail rather "
            "than removing them from the record."
        ),
        "",
        "## Limitations",
        "",
    ]
    lines.extend(f"- {_md(item)}" for item in snapshot["limitations"])
    return "\n".join(lines).rstrip() + "\n"


def _dockpack(
    snapshot: bytes,
    technical: bytes,
    executive: bytes,
    manifest: bytes,
    evidence: list[VerifiedArtifact],
) -> bytes:
    payloads: dict[str, bytes] = {
        "reports/technical.json": snapshot,
        "reports/technical.md": technical,
        "reports/executive.md": executive,
        "evidence/manifest.json": manifest,
    }
    for artifact in evidence:
        payloads[artifact.reference.archive_path] = artifact.payload
    package_manifest = {
        "schema": DOCKPACK_SCHEMA,
        "algorithm": "sha256",
        "snapshot_sha256": sha256(snapshot).hexdigest(),
        "members": [
            {
                "path": path,
                "bytes": len(payloads[path]),
                "sha256": sha256(payloads[path]).hexdigest(),
            }
            for path in sorted(payloads)
        ],
    }
    payloads["dockpack.json"] = _document(package_manifest)
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_STORED, strict_timestamps=True) as archive:
        for name in sorted(payloads):
            info = ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payloads[name])
    return output.getvalue()


def _safe_relative(value: str) -> PurePosixPath:
    if not value or "\\" in value:
        raise ReportRejected("An evidence path is not a safe portable path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReportRejected("An evidence path is not a safe portable path")
    return path


def _safe_file(root: Path, relative: str) -> Path:
    portable = _safe_relative(relative)
    root = root.resolve()
    candidate = root.joinpath(*portable.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ReportRejected("A retained evidence path is unavailable") from error
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ReportRejected("A retained evidence path is unavailable or outside RedLedger")
    return resolved


def _read_bounded(path: Path, max_bytes: int, message: str) -> bytes:
    """Read at most one byte beyond a hard limit, never the whole oversized file."""
    with path.open("rb") as source:
        payload = source.read(max(0, max_bytes) + 1)
    if len(payload) > max_bytes:
        raise ReportRejected(message)
    return payload


def _reject_oversized_collection(rows: list, limit: int, label: str) -> None:
    if len(rows) > limit:
        raise ReportRejected(f"The report exceeds the fixed {label}-count limit")


def _remove_partial_report(store: EvidenceStore, dockyard_id: int, run_id: int) -> None:
    directory = store.run_directory(dockyard_id, run_id, REPORTING_SCOPE)
    reporting_root = (store.root / str(int(dockyard_id)) / REPORTING_SCOPE).resolve()
    resolved = directory.resolve()
    if resolved.parent == reporting_root and resolved.exists():
        shutil.rmtree(resolved)


def _document(value: dict) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode()


def _md(value) -> str:
    """Render untrusted text as one self-contained CommonMark/GFM code span."""
    if value is None:
        return "—"
    text = " ".join(str(value).split())
    longest_run = current_run = 0
    for character in text:
        current_run = current_run + 1 if character == "`" else 0
        longest_run = max(longest_run, current_run)
    delimiter = "`" * (longest_run + 1)
    # CommonMark removes one padding space on each side when the content starts
    # or ends with a backtick, leaving the retained value visible verbatim.
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{delimiter}{padding}{text}{padding}{delimiter}"


def _md_code(value) -> str:
    """Render untrusted text inside an existing Markdown code span."""
    if value is None:
        return "—"
    # A code span already neutralizes every other Markdown construct. Replacing
    # its delimiter preserves the previous public output contract and prevents
    # a retained value from terminating the span.
    return " ".join(str(value).split()).replace("`", "'")


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
