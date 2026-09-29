"""Describe retained assessment coverage without contacting a target."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import DetectionRun, DiscoveryRun, EvidenceRecord, Observation

CHECKS = (
    ("http_headers", "HTTP security headers", ("http_response",), "http.security_headers"),
    ("tls", "TLS certificate verification", ("tls_session",), "tls.certificates"),
    (
        "services", "Identified service rules",
        ("service_identified", "service inventory"), "service.rules",
    ),
)
NOT_SUPPORTED = (
    "UDP discovery", "Credentialed checks", "Exploitability tests",
    "HTTP response bodies", "NSE scripts", "Brute force", "Payloads and evasion",
)


def assessment_coverage(session: Session, dockyard_id: int) -> dict:
    """Count observations from completed, evidence-linked discovery only.

    A check is marked checked only when the latest detection run records that
    detector as successful and observations existed before its input snapshot.
    This is Dockyard-level coverage, never a claim about every scoped target.
    """
    detection = session.scalar(
        select(DetectionRun)
        .where(DetectionRun.dockyard_id == dockyard_id)
        .order_by(DetectionRun.id.desc())
        .limit(1)
    )
    sources = select(EvidenceRecord.discovery_run_id).where(
        EvidenceRecord.dockyard_id == dockyard_id,
        EvidenceRecord.kind == "normalized",
        EvidenceRecord.truncated.is_(False),
    )
    base = (
        select(func.count(Observation.id))
        .join(DiscoveryRun, DiscoveryRun.id == Observation.discovery_run_id)
        .where(
            Observation.dockyard_id == dockyard_id,
            DiscoveryRun.dockyard_id == dockyard_id,
            DiscoveryRun.status == "completed",
            DiscoveryRun.id.in_(sources),
        )
    )
    successful = {
        item["id"] for item in (detection.detectors or [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
        and item.get("status") == "completed"
    } if detection and detection.result_sha256 and detection.metadata_sha256 else set()
    checks = []
    for identifier, title, observation_types, detector in CHECKS:
        query = base.where(Observation.observation_type.in_(observation_types))
        count = session.scalar(query) or 0
        reviewed = 0
        if detector in successful and detection.started_at:
            reviewed = session.scalar(query.where(
                Observation.created_at <= detection.started_at,
                DiscoveryRun.completed_at <= detection.started_at,
            )) or 0
        state = "not_checked"
        if count:
            state = "checked" if reviewed == count else "collected"
        checks.append({
            "id": identifier, "title": title,
            "status": state,
            "observation_count": count,
            "reviewed_observation_count": reviewed,
        })
    return {
        "checks": checks,
        "latest_detection_run_id": detection.id if detection else None,
        "latest_detection_status": detection.status if detection else None,
        "unsupported": list(NOT_SUPPORTED),
        "limitation": (
            "Coverage describes retained observations in this Dockyard, not every allowed "
            "target or vulnerability. Checked does not mean secure. Live coverage uses stored "
            "evidence links; report generation re-verifies the supporting files."
        ),
    }
