"""Phase 3 validation tests use a loopback-only HTTP server.

The validation runner reuses the same bounded HTTP probe as discovery. These
tests prove the approval and DockGuard boundaries around that one request, not
the behaviour of any system outside the test process.
"""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.detection import runner as detection_runner
from app.models import Finding
from tests.phase1 import Recorder


def test_startup_recovers_running_validations_and_preserves_pending(
    client, dockyard_id, header_finding
):
    from app.database import SessionLocal
    from app.main import app
    from app.models import ValidationRun
    from app.reporting.runner import _reject_active_sources

    path = f"/api/dockyards/{dockyard_id}/findings/{header_finding.id}/validations"
    interrupted = client.post(path).json()["id"]
    pending = client.post(path).json()["id"]
    with SessionLocal() as db:
        db.get(ValidationRun, interrupted).status = "running"
        db.commit()
    with TestClient(app, base_url="http://localhost"):
        with SessionLocal() as db:
            recovered = db.get(ValidationRun, interrupted)
            assert recovered.status == "failed"
            assert recovered.completed_at is not None
            assert "restart" in recovered.error
            assert db.get(ValidationRun, pending).status == "pending_approval"
            _reject_active_sources(db, dockyard_id)


def test_stale_approval_loses_atomic_claim_without_probing(
    client, dockyard_id, header_finding, monkeypatch
):
    from sqlalchemy import update

    from app.database import SessionLocal
    from app.models import ValidationRun
    from app.validation import runner

    run_id = client.post(
        f"/api/dockyards/{dockyard_id}/findings/{header_finding.id}/validations"
    ).json()["id"]
    original = runner._evaluate

    def competing_claim(*args):
        decision = original(*args)
        with SessionLocal() as other:
            other.execute(update(ValidationRun).where(ValidationRun.id == run_id).values(
                status="running", approval_note="Winning approval"
            ))
            other.commit()
        return decision

    def unexpected_probe(*_args):
        pytest.fail("A stale approval must never contact the target")

    monkeypatch.setattr(runner, "_evaluate", competing_claim)
    monkeypatch.setattr(runner, "_validate", unexpected_probe)
    with SessionLocal() as db:
        with pytest.raises(runner.ValidationRejected, match="pending"):
            runner.approve_run(db, dockyard_id, run_id, "Losing approval")
    with SessionLocal() as db:
        assert db.get(ValidationRun, run_id).approval_note == "Winning approval"


def test_detection_repairs_a_legacy_missing_evidence_link(
    client, dockyard_id, header_finding, recorder
):
    from app.models import FindingEvidence

    db = recorder.session
    link = db.scalar(select(FindingEvidence).where(
        FindingEvidence.finding_id == header_finding.id
    ))
    expected_record = link.evidence_record_id
    assert expected_record is not None
    link.evidence_record_id = None
    db.commit()
    detection_runner.start_detection(db, dockyard_id)
    db.refresh(link)
    assert link.evidence_record_id == expected_record


class ValidationHandler(BaseHTTPRequestHandler):
    """A loopback endpoint that intentionally keeps plaintext HTTP available."""

    def do_HEAD(self) -> None:  # method name is fixed by BaseHTTPRequestHandler
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args) -> None:
        return


@pytest.fixture()
def origin() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ValidationHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def header_finding(
    client: TestClient,
    recorder: Recorder,
    dockyard_id: int,
    add_scope,
    origin: str,
) -> Finding:
    add_scope(dockyard_id, origin)
    recorder.http_endpoint(origin, headers={})
    detection_runner.start_detection(recorder.session, dockyard_id)
    return recorder.session.scalar(
        select(Finding).where(
            Finding.dockyard_id == dockyard_id,
            Finding.detector == "http.security_headers",
            Finding.rule_id == "plaintext-http",
        )
    )


def test_validation_requires_a_separate_approval_step(
    client: TestClient, dockyard_id: int, header_finding: Finding
):
    requested = client.post(
        f"/api/dockyards/{dockyard_id}/findings/{header_finding.id}/validations"
    )

    assert requested.status_code == 201, requested.text
    run = requested.json()
    assert run["status"] == "pending_approval"
    assert run["outcome"] is None
    assert run["approval_note"] is None

    too_short = client.post(
        f"/api/dockyards/{dockyard_id}/validations/{run['id']}/approve", json={"note": "no"}
    )
    assert too_short.status_code == 422
    assert client.get(f"/api/dockyards/{dockyard_id}/validations/{run['id']}").json()[
        "status"
    ] == "pending_approval"


def test_approved_validation_confirms_a_persisting_http_finding_and_keeps_a_package(
    client: TestClient, dockyard_id: int, header_finding: Finding, environment: Path
):
    run = client.post(
        f"/api/dockyards/{dockyard_id}/findings/{header_finding.id}/validations"
    ).json()
    approved = client.post(
        f"/api/dockyards/{dockyard_id}/validations/{run['id']}/approve",
        json={"note": "Confirm the current transport response."},
    )

    assert approved.status_code == 200, approved.text
    result = approved.json()
    assert (result["status"], result["outcome"], result["confidence"]) == (
        "completed",
        "confirmed",
        "high",
    )
    assert result["evidence_path"] == f"{dockyard_id}/validation/{run['id']}"
    assert result["metadata_sha256"] and result["result_sha256"] and result["manifest_sha256"]

    package = environment / "evidence" / str(dockyard_id) / "validation" / str(run["id"])
    assert (package / "raw" / "http-recheck.json").is_file()
    assert (package / "normalized" / "result.json").is_file()
    assert (package / "metadata.json").is_file()
    assert (package / "raw" / "manifest.json").is_file()

    detail = client.get(f"/api/dockyards/{dockyard_id}/findings/{header_finding.id}").json()
    assert detail["validations"][0]["id"] == run["id"]
    assert detail["validations"][0]["outcome"] == "confirmed"


def test_scope_is_rechecked_at_approval_and_a_denied_validation_never_writes_evidence(
    client: TestClient, dockyard_id: int, header_finding: Finding, environment: Path
):
    run = client.post(
        f"/api/dockyards/{dockyard_id}/findings/{header_finding.id}/validations"
    ).json()
    scope = client.get(f"/api/dockyards/{dockyard_id}/scope").json()
    assert client.delete(f"/api/dockyards/{dockyard_id}/scope/{scope[0]['id']}").status_code == 204

    denied = client.post(
        f"/api/dockyards/{dockyard_id}/validations/{run['id']}/approve",
        json={"note": "Scope changed; verify the gate stops this run."},
    )

    assert denied.status_code == 403, denied.text
    result = denied.json()
    assert result["status"] == "denied"
    assert result["outcome"] is None
    package = environment / "evidence" / str(dockyard_id) / "validation" / str(run["id"])
    assert not package.exists()


def test_a_non_http_finding_has_no_validation_profile(
    client: TestClient, recorder: Recorder, dockyard_id: int
):
    recorder.identified_service("127.0.0.1", 23, service_name="telnet")
    detection_runner.start_detection(recorder.session, dockyard_id)
    finding = recorder.session.scalar(
        select(Finding).where(Finding.detector == "service.rules")
    )
    response = client.post(f"/api/dockyards/{dockyard_id}/findings/{finding.id}/validations")

    assert response.status_code == 409
    assert "no Phase 3" in response.json()["detail"]
