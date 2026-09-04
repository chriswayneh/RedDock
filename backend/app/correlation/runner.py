"""Deterministic Phase 4 correlation over stored RedDock state.

This package has no network or process capability. It accepts no target or
operator options. It records only exact relationships RedDock can explain from
stored identifiers and evidence hashes; it does not infer reachability, attack
paths, exploitability, or aggregate risk.
"""

import logging
from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.correlation.frameworks import FRAMEWORK, RULE_MAPPINGS, VERSION
from app.evidence import CORRELATION_SCOPE, EVIDENCE_SCHEMA, EvidenceStore
from app.models import (
    Asset,
    AssetRelationship,
    CorrelationRun,
    EvidenceRecord,
    Finding,
    FindingCorrelation,
    FindingEvidence,
    FrameworkMapping,
    Observation,
)

logger = logging.getLogger("reddock.correlation")
ACTIVE_STATUSES = ("pending", "running")


class RunRejected(ValueError):
    """Raised when a correlation snapshot cannot safely be started."""


def start_correlation(session: Session, dockyard_id: int) -> CorrelationRun:
    if session.scalar(
        select(func.count()).select_from(CorrelationRun).where(
            CorrelationRun.dockyard_id == dockyard_id,
            CorrelationRun.status.in_(ACTIVE_STATUSES),
        )
    ):
        raise RunRejected("A correlation run is already in flight for this Dockyard")

    run = CorrelationRun(dockyard_id=dockyard_id, status="pending")
    session.add(run)
    session.commit()
    session.refresh(run)
    return _execute(session, run)


def list_runs(session: Session, dockyard_id: int, limit: int) -> list[CorrelationRun]:
    return list(
        session.scalars(
            select(CorrelationRun)
            .where(CorrelationRun.dockyard_id == dockyard_id)
            .order_by(CorrelationRun.id.desc())
            .limit(limit)
        )
    )


def latest_completed(session: Session, dockyard_id: int) -> CorrelationRun | None:
    return session.scalar(
        select(CorrelationRun)
        .where(CorrelationRun.dockyard_id == dockyard_id, CorrelationRun.status == "completed")
        .order_by(CorrelationRun.id.desc())
        .limit(1)
    )


def graph(session: Session, dockyard_id: int) -> dict:
    """Return the latest completed snapshot as a presentation-neutral graph."""
    run = latest_completed(session, dockyard_id)
    if run is None or not isinstance(run.graph, dict):
        return {"run": None, "nodes": [], "edges": [], "mappings": []}
    return {
        "run": run,
        "nodes": run.graph.get("nodes", []),
        "edges": run.graph.get("edges", []),
        "mappings": run.graph.get("mappings", []),
    }


def recover_interrupted_runs(session: Session) -> int:
    rows = list(
        session.scalars(select(CorrelationRun).where(CorrelationRun.status.in_(ACTIVE_STATUSES)))
    )
    for run in rows:
        run.status = "failed"
        run.error = "Interrupted by a RedDock restart"
        run.completed_at = datetime.now(UTC)
    session.commit()
    return len(rows)


def _execute(session: Session, run: CorrelationRun) -> CorrelationRun:
    run.status = "running"
    run.started_at = datetime.now(UTC)
    session.commit()
    try:
        return _perform(session, run)
    except RunRejected as error:
        session.rollback()
        run = session.get(CorrelationRun, run.id)
        if run is None:
            raise
        run.status = "failed"
        run.error = str(error)[:500]
        run.completed_at = datetime.now(UTC)
        session.commit()
        return run
    except Exception:
        logger.exception("Correlation run %s failed unexpectedly", run.id)
        session.rollback()
        run = session.get(CorrelationRun, run.id)
        if run is None:
            raise
        run.status = "failed"
        run.error = "Correlation failed unexpectedly; see the RedDock container log"
        run.completed_at = datetime.now(UTC)
        session.commit()
        return run


def _perform(session: Session, run: CorrelationRun) -> CorrelationRun:
    assets = list(
        session.scalars(
            select(Asset).where(Asset.dockyard_id == run.dockyard_id).order_by(Asset.id)
        )
    )
    findings = list(
        session.scalars(
            select(Finding).where(Finding.dockyard_id == run.dockyard_id).order_by(Finding.id)
        )
    )
    settings = get_settings()
    if len(assets) > settings.max_correlation_assets:
        raise RunRejected(
            f"Correlation input has {len(assets)} assets; fixed limit is "
            f"{settings.max_correlation_assets}"
        )
    if len(findings) > settings.max_correlation_findings:
        raise RunRejected(
            f"Correlation input has {len(findings)} findings; fixed limit is "
            f"{settings.max_correlation_findings}"
        )
    finding_hashes = _finding_hashes(session, findings)
    asset_relationships = _asset_relationships(session, run, assets)
    session.flush()
    subject_edge_count = sum(
        finding.asset_id is not None and finding.id in finding_hashes for finding in findings
    )
    fixed_edge_count = len(asset_relationships) + subject_edge_count
    if fixed_edge_count > settings.max_correlation_edges:
        raise RunRejected(
            f"Correlation would create more than {settings.max_correlation_edges} edges"
        )
    finding_correlations = _finding_correlations(
        run,
        findings,
        finding_hashes,
        asset_relationships,
        settings.max_correlation_edges - fixed_edge_count,
    )
    mappings = _framework_mappings(run, findings, finding_hashes)

    session.add_all([*finding_correlations, *mappings])
    session.flush()
    run.asset_count = len(assets)
    run.finding_count = len(findings)
    run.asset_relationship_count = len(asset_relationships)
    run.finding_correlation_count = len(finding_correlations)
    run.framework_mapping_count = len(mappings)
    run.graph = _graph_document(
        assets,
        findings,
        finding_hashes,
        asset_relationships,
        finding_correlations,
        mappings,
    )
    run.status = "completed"
    session.commit()

    result = _result_document(
        run, assets, findings, asset_relationships, finding_correlations, mappings
    )
    store = EvidenceStore()
    normalized = store.write_normalized(run.dockyard_id, run.id, result, CORRELATION_SCOPE)
    metadata = store.write_metadata(
        run.dockyard_id,
        run.id,
        {
            "schema": EVIDENCE_SCHEMA,
            "kind": "correlation",
            "dockyard_id": run.dockyard_id,
            "run_id": run.id,
            "inputs": {"assets": len(assets), "findings": len(findings)},
            "counts": {
                "asset_relationships": len(asset_relationships),
                "finding_correlations": len(finding_correlations),
                "framework_mappings": len(mappings),
            },
            "method": "exact stored identifiers and evidence hashes",
            "artifacts": [{"path": normalized.relative_path, "sha256": normalized.sha256}],
        },
        CORRELATION_SCOPE,
    )
    run.evidence_path = store.relative_run_path(run.dockyard_id, run.id, CORRELATION_SCOPE)
    run.result_sha256 = normalized.sha256
    run.metadata_sha256 = metadata.sha256
    run.completed_at = datetime.now(UTC)
    session.commit()
    return run


def _finding_hashes(session: Session, findings: list[Finding]) -> dict[int, str]:
    if not findings:
        return {}
    statement = (
        select(FindingEvidence.finding_id, EvidenceRecord.sha256)
        .join(EvidenceRecord, EvidenceRecord.id == FindingEvidence.evidence_record_id)
        .where(FindingEvidence.finding_id.in_([finding.id for finding in findings]))
        .order_by(FindingEvidence.finding_id, FindingEvidence.id)
    )
    hashes: dict[int, str] = {}
    for finding_id, digest in session.execute(statement):
        hashes.setdefault(finding_id, digest)
    return hashes


def _asset_relationships(
    session: Session, run: CorrelationRun, assets: list[Asset]
) -> list[AssetRelationship]:
    hosts = {
        asset.identity: asset
        for asset in assets
        if asset.asset_type == "host" and asset.ip_address == asset.identity
    }
    relationships: list[AssetRelationship] = []
    for web in (asset for asset in assets if asset.asset_type == "web" and asset.ip_address):
        host = hosts.get(web.ip_address or "")
        if host is None or host.id == web.id:
            continue
        observations = session.scalars(
            select(Observation)
            .where(
                Observation.dockyard_id == run.dockyard_id,
                Observation.asset_id == web.id,
                Observation.observation_type == "http_response",
            )
            .order_by(Observation.observed_at.desc(), Observation.id.desc())
            .limit(100)
        )
        observation = next(
            (
                row
                for row in observations
                if isinstance(row.detail, dict) and row.detail.get("address") == web.ip_address
            ),
            None,
        )
        if observation is None or observation.discovery_run_id is None:
            continue
        evidence = session.scalar(
            select(EvidenceRecord)
            .where(
                EvidenceRecord.dockyard_id == run.dockyard_id,
                EvidenceRecord.discovery_run_id == observation.discovery_run_id,
                EvidenceRecord.kind == "normalized",
            )
            .order_by(EvidenceRecord.id)
            .limit(1)
        )
        if evidence is None:
            continue
        relationship = AssetRelationship(
            correlation_run_id=run.id,
            dockyard_id=run.dockyard_id,
            source_asset_id=web.id,
            target_asset_id=host.id,
            relationship_type="observed_at_address",
            confidence="observed",
            basis=(
                f"Stored observation #{observation.id} places {web.identity} at the exact "
                f"address recorded by host asset {host.identity}."
            ),
            observation_id=observation.id,
            discovery_run_id=observation.discovery_run_id,
            evidence_record_id=evidence.id,
            evidence_sha256=evidence.sha256,
        )
        session.add(relationship)
        relationships.append(relationship)
    return relationships


def _finding_correlations(
    run: CorrelationRun,
    findings: list[Finding],
    hashes: dict[int, str],
    asset_relationships: list[AssetRelationship],
    limit: int,
) -> list[FindingCorrelation]:
    by_asset: dict[int, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.asset_id is not None and finding.id in hashes:
            by_asset[finding.asset_id].append(finding)

    rows: list[FindingCorrelation] = []
    seen: set[tuple[int, int, str]] = set()

    def add(left: Finding, right: Finding, kind: str, basis: str, relation_id: int | None) -> None:
        source, target = sorted((left, right), key=lambda item: item.id)
        key = (source.id, target.id, kind)
        if source.id == target.id or key in seen:
            return
        if len(rows) >= limit:
            raise RunRejected(
                f"Correlation would create more than {get_settings().max_correlation_edges} edges"
            )
        seen.add(key)
        rows.append(
            FindingCorrelation(
                correlation_run_id=run.id,
                dockyard_id=run.dockyard_id,
                source_finding_id=source.id,
                target_finding_id=target.id,
                relationship_type=kind,
                confidence="observed",
                basis=basis,
                asset_relationship_id=relation_id,
                source_evidence_sha256=hashes[source.id],
                target_evidence_sha256=hashes[target.id],
            )
        )

    for asset_id, grouped in by_asset.items():
        for index, left in enumerate(grouped):
            for right in grouped[index + 1 :]:
                add(
                    left,
                    right,
                    "same_asset",
                    f"Both findings cite observations attached to asset #{asset_id}.",
                    None,
                )

    for relationship in asset_relationships:
        for left in by_asset.get(relationship.source_asset_id, []):
            for right in by_asset.get(relationship.target_asset_id, []):
                add(
                    left,
                    right,
                    "related_assets",
                    (
                        "The findings belong to assets joined by asset relationship "
                        f"#{relationship.id}."
                    ),
                    relationship.id,
                )
    return rows


def _framework_mappings(
    run: CorrelationRun, findings: list[Finding], hashes: dict[int, str]
) -> list[FrameworkMapping]:
    rows: list[FrameworkMapping] = []
    for finding in findings:
        mapping = RULE_MAPPINGS.get(finding.rule_id)
        digest = hashes.get(finding.id)
        if mapping is None or digest is None:
            continue
        rows.append(
            FrameworkMapping(
                correlation_run_id=run.id,
                dockyard_id=run.dockyard_id,
                finding_id=finding.id,
                framework=FRAMEWORK,
                external_id=mapping.external_id,
                title=mapping.title,
                basis=(
                    "Fixed RedDock mapping for detector rule "
                    f"{finding.detector}/{finding.rule_id}."
                ),
                mapping_version=VERSION,
                evidence_sha256=digest,
            )
        )
    return rows


def _graph_document(
    assets: list[Asset],
    findings: list[Finding],
    hashes: dict[int, str],
    relationships: list[AssetRelationship],
    correlations: list[FindingCorrelation],
    mappings: list[FrameworkMapping],
) -> dict:
    nodes = [
        {
            "id": f"asset:{asset.id}",
            "kind": "asset",
            "label": asset.display_name,
            "subtitle": asset.asset_type,
            "status": None,
            "severity": None,
        }
        for asset in assets
    ] + [
        {
            "id": f"finding:{finding.id}",
            "kind": "finding",
            "label": finding.title,
            "subtitle": finding.rule_id,
            "status": finding.status,
            "severity": finding.severity,
        }
        for finding in findings
    ]
    edges = [
        {
            "id": f"asset-relationship:{row.id}",
            "source": f"asset:{row.source_asset_id}",
            "target": f"asset:{row.target_asset_id}",
            "kind": "asset_relationship",
            "label": row.relationship_type,
            "confidence": row.confidence,
            "basis": row.basis,
            "evidence_sha256": [row.evidence_sha256] if row.evidence_sha256 else [],
        }
        for row in relationships
    ]
    edges.extend(
        {
            "id": f"finding-subject:{finding.id}",
            "source": f"asset:{finding.asset_id}",
            "target": f"finding:{finding.id}",
            "kind": "finding_subject",
            "label": "supported finding",
            "confidence": finding.confidence,
            "basis": (
                f"Finding #{finding.id} cites observations attached to "
                f"asset #{finding.asset_id}."
            ),
            "evidence_sha256": [hashes[finding.id]],
        }
        for finding in findings
        if finding.asset_id is not None and finding.id in hashes
    )
    edges.extend(
        {
            "id": f"finding-correlation:{row.id}",
            "source": f"finding:{row.source_finding_id}",
            "target": f"finding:{row.target_finding_id}",
            "kind": "finding_correlation",
            "label": row.relationship_type,
            "confidence": row.confidence,
            "basis": row.basis,
            "evidence_sha256": [
                digest
                for digest in (row.source_evidence_sha256, row.target_evidence_sha256)
                if digest
            ],
        }
        for row in correlations
    )
    return {
        "nodes": nodes,
        "edges": edges,
        "mappings": [
            {
                "id": row.id,
                "finding_id": row.finding_id,
                "framework": row.framework,
                "external_id": row.external_id,
                "title": row.title,
                "basis": row.basis,
                "mapping_version": row.mapping_version,
                "evidence_sha256": row.evidence_sha256,
            }
            for row in mappings
        ],
    }


def _result_document(run, assets, findings, relationships, correlations, mappings) -> dict:
    return {
        "schema": EVIDENCE_SCHEMA,
        "run_id": run.id,
        "assets": [
            {"id": asset.id, "type": asset.asset_type, "identity": asset.identity}
            for asset in assets
        ],
        "findings": [
            {"id": finding.id, "rule_id": finding.rule_id, "title": finding.title}
            for finding in findings
        ],
        "asset_relationships": [
            {
                "source_asset_id": row.source_asset_id,
                "target_asset_id": row.target_asset_id,
                "type": row.relationship_type,
                "basis": row.basis,
                "observation_id": row.observation_id,
                "evidence_sha256": row.evidence_sha256,
            }
            for row in relationships
        ],
        "finding_correlations": [
            {
                "source_finding_id": row.source_finding_id,
                "target_finding_id": row.target_finding_id,
                "type": row.relationship_type,
                "basis": row.basis,
                "source_evidence_sha256": row.source_evidence_sha256,
                "target_evidence_sha256": row.target_evidence_sha256,
            }
            for row in correlations
        ],
        "framework_mappings": [
            {
                "finding_id": row.finding_id,
                "framework": row.framework,
                "external_id": row.external_id,
                "title": row.title,
                "basis": row.basis,
                "evidence_sha256": row.evidence_sha256,
            }
            for row in mappings
        ],
    }
