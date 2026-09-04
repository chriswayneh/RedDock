"""Phase 4 correlation is stored-state-only, explainable, and evidence-linked."""

import ast
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.correlation import runner
from app.models import (
    Asset,
    AssetRelationship,
    Finding,
    FindingCorrelation,
    FrameworkMapping,
    Observation,
)


def _prepared(recorder, session: Session, dockyard_id: int) -> None:
    recorder.identified_service(
        "127.0.0.1", 23, service_name="telnet", product="Example daemon", version="1.0"
    )
    recorder.http_endpoint("http://127.0.0.1:8080", headers={"server": "example"}, port=8080)
    from app.detection.runner import start_detection

    detected = start_detection(session, dockyard_id)
    assert detected.status == "completed"


def test_correlation_builds_only_hashed_explainable_relationships(
    recorder, session: Session, dockyard_id: int
):
    _prepared(recorder, session, dockyard_id)

    run = runner.start_correlation(session, dockyard_id)

    assert run.status == "completed"
    assert run.asset_relationship_count == 1
    assert run.finding_correlation_count > 0
    assert run.framework_mapping_count > 0
    assert run.evidence_path == f"{dockyard_id}/correlation/{run.id}"
    assert len(run.metadata_sha256 or "") == 64
    assert len(run.result_sha256 or "") == 64

    relationship = session.scalar(
        select(AssetRelationship).where(AssetRelationship.correlation_run_id == run.id)
    )
    assert relationship is not None
    assert relationship.relationship_type == "observed_at_address"
    assert "Stored observation" in relationship.basis
    assert relationship.evidence_sha256 == "a" * 64

    correlations = list(
        session.scalars(
            select(FindingCorrelation).where(FindingCorrelation.correlation_run_id == run.id)
        )
    )
    assert {row.relationship_type for row in correlations} >= {"same_asset", "related_assets"}
    assert all(
        row.basis and row.source_evidence_sha256 and row.target_evidence_sha256
        for row in correlations
    )

    mappings = list(
        session.scalars(
            select(FrameworkMapping).where(FrameworkMapping.correlation_run_id == run.id)
        )
    )
    assert {(row.framework, row.external_id) for row in mappings} >= {
        ("CWE", "CWE-319"),
        ("CWE", "CWE-200"),
    }
    assert all(row.basis and row.evidence_sha256 == "a" * 64 for row in mappings)


def test_redpath_api_is_dockyard_isolated_and_rejects_operator_options(
    client: TestClient, recorder, session: Session, dockyard_id: int
):
    _prepared(recorder, session, dockyard_id)

    rejected = client.post(
        f"/api/dockyards/{dockyard_id}/correlations", json={"target": "127.0.0.1"}
    )
    assert rejected.status_code == 422

    response = client.post(f"/api/dockyards/{dockyard_id}/correlations", json={})
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "completed"

    graph = client.get(f"/api/dockyards/{dockyard_id}/redpath")
    assert graph.status_code == 200
    body = graph.json()
    assert body["run"]["id"] == response.json()["id"]
    assert {node["kind"] for node in body["nodes"]} == {"asset", "finding"}
    assert {edge["kind"] for edge in body["edges"]} >= {
        "asset_relationship",
        "finding_subject",
        "finding_correlation",
    }
    assert all(edge["basis"] and edge["evidence_sha256"] for edge in body["edges"])
    assert all(mapping["evidence_sha256"] for mapping in body["mappings"])

    original_nodes = body["nodes"]
    stored_asset = session.scalar(select(Asset).where(Asset.dockyard_id == dockyard_id))
    stored_finding = session.scalar(select(Finding).where(Finding.dockyard_id == dockyard_id))
    assert stored_asset is not None and stored_finding is not None
    stored_asset.display_name = "Changed after the snapshot"
    stored_finding.title = "Changed after the snapshot"
    session.commit()
    assert client.get(f"/api/dockyards/{dockyard_id}/redpath").json()["nodes"] == original_nodes

    other = client.post("/api/dockyards", json={"name": "Other"}).json()["id"]
    empty = client.get(f"/api/dockyards/{other}/redpath").json()
    assert empty == {"run": None, "nodes": [], "edges": [], "mappings": []}


def test_asset_relationship_requires_the_exact_response_address(
    recorder, session: Session, dockyard_id: int
):
    recorder.identified_service("127.0.0.1", 80, service_name="http")
    web, _, _ = recorder.http_endpoint("http://127.0.0.1")
    response = session.scalar(
        select(Observation).where(
            Observation.asset_id == web.id,
            Observation.observation_type == "http_response",
        )
    )
    assert response is not None and response.detail is not None
    response.detail = {**response.detail, "address": "127.0.0.2"}
    session.commit()

    run = runner.start_correlation(session, dockyard_id)
    assert run.status == "completed"
    assert run.asset_relationship_count == 0


def test_edge_limit_fails_the_snapshot_before_dense_correlation(
    recorder, session: Session, dockyard_id: int, monkeypatch
):
    from app.config import get_settings

    _prepared(recorder, session, dockyard_id)
    monkeypatch.setattr(get_settings(), "max_correlation_edges", 1)

    run = runner.start_correlation(session, dockyard_id)

    assert run.status == "failed"
    assert run.error == "Correlation would create more than 1 edges"
    assert runner.latest_completed(session, dockyard_id) is None


def test_correlation_package_has_no_active_capability():
    root = Path(__file__).parents[1] / "app" / "correlation"
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
