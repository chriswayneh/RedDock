from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.coverage import assessment_coverage
from app.detection.runner import start_detection
from app.models import DiscoveryRun, EvidenceRecord, Observation


def test_empty_coverage_does_not_claim_checks(client: TestClient, dockyard_id: int):
    response = client.get(f"/api/dockyards/{dockyard_id}/coverage")
    assert response.status_code == 200
    assert all(check["status"] == "not_checked" for check in response.json()["checks"])
    assert client.get("/api/dockyards/999999/coverage").status_code == 404


def _complete_sources(recorder, session: Session, dockyard_id: int, port: int = 8080):
    recorder.http_endpoint(f"http://127.0.0.1:{port}", headers={}, port=port)
    for run in session.scalars(select(DiscoveryRun).where(DiscoveryRun.dockyard_id == dockyard_id)):
        run.completed_at = datetime.now(UTC) - timedelta(seconds=1)
    session.commit()


def test_coverage_requires_detector_success_and_retained_source(
    recorder, session: Session, dockyard_id: int,
):
    _complete_sources(recorder, session, dockyard_id)
    before = assessment_coverage(session, dockyard_id)
    assert before["checks"][0]["status"] == "collected"
    detection = start_detection(session, dockyard_id)
    assert detection.status == "completed"
    reviewed = assessment_coverage(session, dockyard_id)
    assert reviewed["checks"][0]["status"] == "checked"
    assert reviewed["checks"][1]["status"] == "not_checked"

    detection.detectors = [{"id": "http.security_headers", "status": "failed"}]
    session.commit()
    assert assessment_coverage(session, dockyard_id)["checks"][0]["status"] == "collected"

    session.query(EvidenceRecord).filter(EvidenceRecord.dockyard_id == dockyard_id).delete()
    session.commit()
    assert assessment_coverage(session, dockyard_id)["checks"][0]["status"] == "not_checked"


def test_later_observations_are_not_claimed_as_reviewed(
    recorder, session: Session, dockyard_id: int,
):
    _complete_sources(recorder, session, dockyard_id)
    start_detection(session, dockyard_id)
    earlier = assessment_coverage(session, dockyard_id)["checks"][0]["reviewed_observation_count"]
    _complete_sources(recorder, session, dockyard_id, port=8081)
    latest = session.scalar(select(Observation).order_by(Observation.id.desc()).limit(1))
    # Make the new discovery completion and observations unambiguously later.
    run = session.get(DiscoveryRun, latest.discovery_run_id)
    run.completed_at = datetime.now(UTC) + timedelta(seconds=1)
    session.commit()
    coverage = assessment_coverage(session, dockyard_id)["checks"][0]
    assert coverage["observation_count"] > earlier
    assert coverage["reviewed_observation_count"] == earlier
    assert coverage["status"] == "collected"


def test_coverage_is_scoped_and_excludes_failed_sources(
    recorder, session: Session, dockyard_id: int, client: TestClient,
):
    _complete_sources(recorder, session, dockyard_id)
    other = client.post("/api/dockyards", json={"name": "Other"}).json()["id"]
    assert all(
        check["observation_count"] == 0
        for check in assessment_coverage(session, other)["checks"]
    )
    for run in session.scalars(select(DiscoveryRun).where(DiscoveryRun.dockyard_id == dockyard_id)):
        run.status = "failed"
    session.commit()
    assert all(
        check["observation_count"] == 0
        for check in assessment_coverage(session, dockyard_id)["checks"]
    )


@pytest.mark.parametrize("hash_field", ["result_sha256", "metadata_sha256"])
def test_incomplete_detection_receipt_never_claims_checked(
    recorder, session: Session, dockyard_id: int, hash_field: str,
):
    _complete_sources(recorder, session, dockyard_id)
    detection = start_detection(session, dockyard_id)
    setattr(detection, hash_field, None)
    session.commit()
    assert assessment_coverage(session, dockyard_id)["checks"][0]["status"] == "collected"


def test_truncated_sources_and_malformed_detector_receipts_are_not_checked(
    recorder, session: Session, dockyard_id: int,
):
    _complete_sources(recorder, session, dockyard_id)
    detection = start_detection(session, dockyard_id)
    detection.detectors = [{"status": "completed"}]
    session.commit()
    assert assessment_coverage(session, dockyard_id)["checks"][0]["status"] == "collected"
    for source in session.scalars(select(EvidenceRecord)):
        source.truncated = True
    session.commit()
    assert assessment_coverage(session, dockyard_id)["checks"][0]["status"] == "not_checked"
