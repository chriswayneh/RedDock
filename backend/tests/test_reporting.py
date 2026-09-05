"""Phase 6 reporting is deterministic, evidence-complete, and read-only."""

import ast
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    DiscoveryRun,
    EvidenceRecord,
    Finding,
    LabAuditEvent,
    LabAuthorization,
    ReportRun,
)
from app.reporting import runner as reporting_runner


def _prepared(recorder, session: Session, dockyard_id: int, environment: Path) -> None:
    recorder.identified_service(
        "127.0.0.1", 23, service_name="telnet", product="Example daemon", version="1.0"
    )
    recorder.http_endpoint("http://127.0.0.1:8080", headers={"server": "example"}, port=8080)
    for record in session.scalars(
        select(EvidenceRecord).where(EvidenceRecord.dockyard_id == dockyard_id)
    ):
        payload = json.dumps(
            {"discovery_run_id": record.discovery_run_id, "kind": record.kind},
            sort_keys=True,
        ).encode()
        path = (
            environment
            / "evidence"
            / str(dockyard_id)
            / str(record.discovery_run_id)
            / record.relative_path
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        record.size_bytes = len(payload)
        record.sha256 = sha256(payload).hexdigest()
    session.commit()
    from app.correlation.runner import start_correlation
    from app.detection.runner import start_detection

    assert start_detection(session, dockyard_id).status == "completed"
    assert start_correlation(session, dockyard_id).status == "completed"


def test_report_set_is_complete_hash_linked_and_portable(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    environment: Path,
):
    _prepared(recorder, session, dockyard_id, environment)
    before = {finding.id: finding.status for finding in session.scalars(select(Finding))}

    rejected = client.post(f"/api/dockyards/{dockyard_id}/reports", json={"path": "outside.zip"})
    assert rejected.status_code == 422
    response = client.post(f"/api/dockyards/{dockyard_id}/reports", json={})
    assert response.status_code == 201, response.text
    report = response.json()
    assert report["status"] == "completed"
    assert report["report_schema"] == "reddock.reporting/2"
    for field in (
        "snapshot_sha256",
        "technical_sha256",
        "executive_sha256",
        "manifest_sha256",
        "dockpack_sha256",
    ):
        assert len(report[field]) == 64
    assert report["dockpack_bytes"] > 0
    assert report["source_counts"]["findings"] > 0

    technical = client.get(f"/api/dockyards/{dockyard_id}/reports/{report['id']}/technical")
    executive = client.get(f"/api/dockyards/{dockyard_id}/reports/{report['id']}/executive")
    manifest_response = client.get(f"/api/dockyards/{dockyard_id}/reports/{report['id']}/manifest")
    assert technical.status_code == executive.status_code == manifest_response.status_code == 200
    assert "RedDock technical report" in technical.text
    assert "RedDock executive report" in executive.text
    assert "aggregate risk score" in executive.text
    manifest = manifest_response.json()
    assert manifest["schema"] == "reddock.evidence-manifest/1"
    assert manifest["dockyard_id"] == dockyard_id
    assert manifest["generator"]["version"] == "0.8.0"
    assert len(manifest["scope_sha256"]) == 64
    assert manifest["skipped_findings"] == []
    assert manifest["file_count"] >= 6
    assert all(len(item["sha256"]) == 64 for item in manifest["files"])
    file_hashes = {item["sha256"] for item in manifest["files"]}
    assert len(manifest["findings"]) == report["source_counts"]["findings"]
    assert all(
        claim["evidence"] and all(item["sha256"] in file_hashes for item in claim["evidence"])
        for claim in manifest["findings"]
    )

    download = client.get(f"/api/dockyards/{dockyard_id}/reports/{report['id']}/dockpack")
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/zip"
    assert sha256(download.content).hexdigest() == report["dockpack_sha256"]
    with ZipFile(BytesIO(download.content)) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert len(names) == len(set(names))
        assert all(not name.startswith("/") and ".." not in name.split("/") for name in names)
        assert {
            "dockpack.json",
            "reports/technical.json",
            "reports/technical.md",
            "reports/executive.md",
            "evidence/manifest.json",
        } <= set(names)
        package = json.loads(archive.read("dockpack.json"))
        assert package["schema"] == "reddock.dockpack/1"
        for member in package["members"]:
            payload = archive.read(member["path"])
            assert len(payload) == member["bytes"]
            assert sha256(payload).hexdigest() == member["sha256"]
        exported_manifest = json.loads(archive.read("evidence/manifest.json"))
        for item in exported_manifest["files"]:
            assert sha256(archive.read(item["archive_path"])).hexdigest() == item["sha256"]
        archived_hashes = {item["sha256"] for item in exported_manifest["files"]}
        assert all(
            evidence["sha256"] in archived_hashes
            for claim in exported_manifest["findings"]
            for evidence in claim["evidence"]
        )

    session.expire_all()
    assert {finding.id: finding.status for finding in session.scalars(select(Finding))} == before


def test_unchanged_state_produces_byte_identical_reports(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    environment: Path,
):
    _prepared(recorder, session, dockyard_id, environment)
    first = client.post(f"/api/dockyards/{dockyard_id}/reports", json={}).json()
    first_pack = client.get(f"/api/dockyards/{dockyard_id}/reports/{first['id']}/dockpack").content
    second = client.post(f"/api/dockyards/{dockyard_id}/reports", json={}).json()
    second_pack = client.get(
        f"/api/dockyards/{dockyard_id}/reports/{second['id']}/dockpack"
    ).content

    assert first["status"] == second["status"] == "completed"
    for field in (
        "snapshot_sha256",
        "technical_sha256",
        "executive_sha256",
        "manifest_sha256",
        "dockpack_sha256",
    ):
        assert first[field] == second[field]
    assert first_pack == second_pack


def test_lab_policy_history_is_bounded_isolated_and_portable(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    environment: Path,
):
    _prepared(recorder, session, dockyard_id, environment)
    other = client.post("/api/dockyards", json={"name": "Other lab"}).json()["id"]
    now = datetime(2026, 9, 5, 7, 0, tzinfo=UTC)
    authorization = LabAuthorization(
        dockyard_id=dockyard_id,
        capability="discovery.nmap.extended-service",
        status="revoked",
        acknowledgement=(
            "I confirm this Dockyard is an isolated lab that I am authorized to test."
        ),
        note="Approved range review | retained literally",
        created_at=now,
        expires_at=now + timedelta(minutes=60),
        revoked_at=now + timedelta(minutes=5),
    )
    session.add(authorization)
    session.flush()
    session.add_all(
        [
            LabAuditEvent(
                dockyard_id=dockyard_id,
                capability=authorization.capability,
                action="authorize",
                decision="allowed",
                reason="Explicit Dockyard acknowledgement",
                authorization_id=authorization.id,
                created_at=now,
            ),
            LabAuditEvent(
                dockyard_id=dockyard_id,
                capability=authorization.capability,
                action="execute",
                decision="denied",
                reason="Authorization revoked before execution",
                authorization_id=authorization.id,
                discovery_run_id=None,
                created_at=now + timedelta(minutes=6),
            ),
        ]
    )
    session.add(
        LabAuditEvent(
            dockyard_id=other,
            capability=authorization.capability,
            action="authorize",
            decision="allowed",
            reason="Must not cross Dockyard boundary",
            created_at=now,
        )
    )
    session.commit()

    report = client.post(f"/api/dockyards/{dockyard_id}/reports", json={}).json()
    package = client.get(
        f"/api/dockyards/{dockyard_id}/reports/{report['id']}/dockpack"
    ).content

    assert report["status"] == "completed"
    assert report["source_counts"]["lab_authorizations"] == 1
    assert report["source_counts"]["lab_audit_events"] == 2
    assert report["source_counts"]["lab_decisions"] == {"allowed": 1, "denied": 1}
    with ZipFile(BytesIO(package)) as archive:
        snapshot = json.loads(archive.read("reports/technical.json"))
        technical = archive.read("reports/technical.md").decode()
    assert snapshot["schema"] == "reddock.reporting/2"
    assert [row["id"] for row in snapshot["lab"]["audit_events"]] == sorted(
        row["id"] for row in snapshot["lab"]["audit_events"]
    )
    assert len(snapshot["lab"]["authorizations"]) == 1
    assert len(snapshot["lab"]["audit_events"]) == 2
    assert "Must not cross Dockyard boundary" not in json.dumps(snapshot)
    assert "## Lab authorization and policy audit" in technical
    assert reporting_runner._md(authorization.note) in technical


def test_lab_audit_report_limit_fails_closed(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    environment: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    _prepared(recorder, session, dockyard_id, environment)
    session.add(
        LabAuditEvent(
            dockyard_id=dockyard_id,
            capability="discovery.nmap.extended-service",
            action="request",
            decision="denied",
            reason="No authorization",
        )
    )
    session.commit()
    settings = reporting_runner.get_settings().model_copy(
        update={"max_report_lab_audit_events": 0}
    )
    monkeypatch.setattr(reporting_runner, "get_settings", lambda: settings)

    response = client.post(f"/api/dockyards/{dockyard_id}/reports", json={})

    assert response.status_code == 201
    assert response.json()["status"] == "failed"
    assert response.json()["error"] == "The report exceeds the fixed lab-audit-event-count limit"


def test_changed_or_missing_evidence_fails_closed(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    environment: Path,
):
    _prepared(recorder, session, dockyard_id, environment)
    record = session.scalar(
        select(EvidenceRecord)
        .where(EvidenceRecord.dockyard_id == dockyard_id)
        .order_by(EvidenceRecord.id)
    )
    assert record is not None
    path = (
        environment
        / "evidence"
        / str(dockyard_id)
        / str(record.discovery_run_id)
        / record.relative_path
    )
    path.write_bytes(b"changed after retention")

    response = client.post(f"/api/dockyards/{dockyard_id}/reports", json={})
    assert response.status_code == 201
    failed = response.json()
    assert failed["status"] == "failed"
    assert "no longer matches" in failed["error"]
    assert failed["dockpack_sha256"] is None


def test_download_rechecks_report_hash_and_dockyard_ownership(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    environment: Path,
):
    _prepared(recorder, session, dockyard_id, environment)
    report = client.post(f"/api/dockyards/{dockyard_id}/reports", json={}).json()
    package = (
        environment
        / "evidence"
        / str(dockyard_id)
        / "reporting"
        / str(report["id"])
        / "raw"
        / "dockpack.zip"
    )
    package.write_bytes(b"tampered")
    response = client.get(f"/api/dockyards/{dockyard_id}/reports/{report['id']}/dockpack")
    assert response.status_code == 409
    assert "no longer matches" in response.json()["detail"]

    other = client.post("/api/dockyards", json={"name": "Other"}).json()["id"]
    assert client.get(f"/api/dockyards/{other}/reports/{report['id']}").status_code == 404
    assert client.get(f"/api/dockyards/{other}/reports/{report['id']}/dockpack").status_code == 404


def test_untrusted_text_is_neutralized_in_markdown(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    environment: Path,
):
    _prepared(recorder, session, dockyard_id, environment)
    finding = session.scalar(select(Finding).where(Finding.dockyard_id == dockyard_id))
    assert finding is not None
    finding.title = "<script>alert(1)</script> | ![beacon](https://attacker.invalid/pixel)"
    finding.description = (
        r"\\[parity](https://attacker.invalid) [local](file:///etc/passwd) "
        "https://attacker.invalid/raw # forged *emphasis* ~~~"
    )
    session.commit()
    report = client.post(f"/api/dockyards/{dockyard_id}/reports", json={}).json()
    technical = client.get(f"/api/dockyards/{dockyard_id}/reports/{report['id']}/technical").text
    assert (
        f"### Finding #{finding.id} — {reporting_runner._md(finding.title)}" in technical
    )
    assert reporting_runner._md(finding.description) in technical


def test_markdown_code_fields_remain_literal_and_cannot_close_the_span():
    value = "https://host.invalid/a_[x](y)<tag>`tail"
    rendered = reporting_runner._md_code(value)

    assert rendered == "https://host.invalid/a_[x](y)<tag>'tail"
    assert "`" not in rendered


def test_markdown_text_uses_a_delimiter_longer_than_any_untrusted_run():
    value = "`edge`` ![beacon](https://attacker.invalid) foo@attacker.invalid `"
    rendered = reporting_runner._md(value)

    assert rendered.startswith("``` ")
    assert rendered.endswith(" ```")
    assert value in rendered


def test_bounded_reader_never_allocates_the_whole_oversized_file(tmp_path: Path):
    artifact = tmp_path / "oversized.bin"
    artifact.write_bytes(b"x" * 128)

    with pytest.raises(reporting_runner.ReportRejected, match="fixed test limit"):
        reporting_runner._read_bounded(artifact, 8, "fixed test limit")


def test_reference_limit_fails_before_building_an_unbounded_manifest(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    environment: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    _prepared(recorder, session, dockyard_id, environment)
    settings = reporting_runner.get_settings().model_copy(
        update={"max_report_evidence_files": 1}
    )
    monkeypatch.setattr(reporting_runner, "get_settings", lambda: settings)

    response = client.post(f"/api/dockyards/{dockyard_id}/reports", json={})

    assert response.status_code == 409
    assert response.json()["detail"] == "The evidence manifest exceeds the fixed file-count limit"


def test_restart_recovery_removes_partial_sensitive_report(
    session: Session, dockyard_id: int, environment: Path
):
    run = ReportRun(dockyard_id=dockyard_id, status="running", report_schema="test/1")
    session.add(run)
    session.commit()
    session.refresh(run)
    directory = environment / "evidence" / str(dockyard_id) / "reporting" / str(run.id)
    directory.mkdir(parents=True)
    (directory / "partial.md").write_text("sensitive", encoding="utf-8")

    assert reporting_runner.recover_interrupted_runs(session) == 1

    session.refresh(run)
    assert run.status == "failed"
    assert not directory.exists()


def test_reporting_requires_retained_evidence(client: TestClient, dockyard_id: int):
    response = client.post(f"/api/dockyards/{dockyard_id}/reports", json={})
    assert response.status_code == 409
    assert response.json()["detail"] == "No retained evidence is available to report"


def test_reporting_rejects_an_active_source_snapshot(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    environment: Path,
):
    _prepared(recorder, session, dockyard_id, environment)
    run = session.scalar(
        select(DiscoveryRun)
        .where(DiscoveryRun.dockyard_id == dockyard_id)
        .order_by(DiscoveryRun.id)
    )
    assert run is not None
    run.status = "pending"
    session.commit()

    response = client.post(f"/api/dockyards/{dockyard_id}/reports", json={})
    assert response.status_code == 409
    assert response.json()["detail"] == "Wait for active Dockyard runs to finish before reporting"


def test_reporting_records_failure_for_a_missing_retained_file(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    environment: Path,
):
    _prepared(recorder, session, dockyard_id, environment)
    record = session.scalar(
        select(EvidenceRecord)
        .where(EvidenceRecord.dockyard_id == dockyard_id)
        .order_by(EvidenceRecord.id)
    )
    assert record is not None
    path = (
        environment
        / "evidence"
        / str(dockyard_id)
        / str(record.discovery_run_id)
        / record.relative_path
    )
    path.unlink()

    response = client.post(f"/api/dockyards/{dockyard_id}/reports", json={})
    assert response.status_code == 201
    report = response.json()
    assert report["status"] == "failed"
    assert report["error"] == "A retained evidence path is unavailable"
    assert report["dockpack_sha256"] is None


def test_reporting_package_has_no_active_capability():
    root = Path(__file__).parents[1] / "app" / "reporting"
    forbidden_imports = {"socket", "subprocess", "urllib", "http", "requests", "httpx"}
    forbidden_calls = {"eval", "exec", "compile", "__import__"}
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = {
            node.names[0].name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
        }
        imports |= {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert not imports & forbidden_imports, path
        assert not calls & forbidden_calls, path
