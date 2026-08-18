import json
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.discovery import registry
from app.discovery import runner as discovery_runner
from app.discovery.base import (
    AdapterError,
    AdapterRequest,
    AdapterResult,
    AssetType,
    Confidence,
    DiscoveredAsset,
    DiscoveredObservation,
    DiscoveredService,
    DiscoveryAdapter,
    Profile,
    RawArtifact,
)
from app.targets import TargetKind


class StubAdapter(DiscoveryAdapter):
    """A recording adapter so tests observe orchestration, not nmap."""

    name = "stub"
    version = "9.9.9"
    title = "Stub"
    description = "Deterministic adapter used by the test suite."
    profiles = (Profile(name="safe", title="Safe", description="Test profile."),)
    supported_kinds = (TargetKind.IPV4, TargetKind.HOSTNAME)

    def __init__(self, failure: Exception | None = None) -> None:
        self.requests: list[AdapterRequest] = []
        self.failure = failure

    def run(self, request: AdapterRequest) -> AdapterResult:
        self.requests.append(request)
        if self.failure is not None:
            raise self.failure
        return AdapterResult(
            assets=(
                DiscoveredAsset(
                    asset_type=AssetType.HOST,
                    identity="127.0.0.1",
                    display_name="127.0.0.1",
                    ip_address="127.0.0.1",
                    services=(DiscoveredService(transport="tcp", port=8080, state="open"),),
                ),
            ),
            observations=(
                DiscoveredObservation(
                    observation_type="port_state",
                    summary="TCP/8080 open on 127.0.0.1",
                    confidence=Confidence.OBSERVED,
                    asset_identity="127.0.0.1",
                    service_port=("tcp", 8080),
                ),
            ),
            artifacts=(
                RawArtifact(
                    name="stub.json", media_type="application/json", content=b'{"ok": true}'
                ),
            ),
            tool_version="stub 1.0",
            invocation=("stub", "127.0.0.1"),
        )


@pytest.fixture()
def adapter(monkeypatch: pytest.MonkeyPatch) -> StubAdapter:
    stub = StubAdapter()
    _install(monkeypatch, stub)
    return stub


def _install(monkeypatch: pytest.MonkeyPatch, stub: StubAdapter) -> None:
    monkeypatch.setattr(registry, "get_adapter", lambda name: stub if name == stub.name else None)
    monkeypatch.setattr(registry, "available_adapters", lambda: (stub,))
    # Run discovery inline so assertions see a finished run.
    monkeypatch.setattr(discovery_runner, "submit_run", discovery_runner.execute_run)


def start(client: TestClient, dockyard: int, target: str) -> dict:
    return client.post(
        f"/api/dockyards/{dockyard}/discoveries",
        json={"target": target, "adapter": "stub", "profile": "safe"},
    )


def test_out_of_scope_target_is_denied_server_side(
    client: TestClient, dockyard_id: int, adapter: StubAdapter, add_scope
):
    add_scope(dockyard_id, "127.0.0.1")
    response = start(client, dockyard_id, "10.0.0.5")

    assert response.status_code == 403
    assert response.json()["decision"] == "denied_out_of_scope"
    assert response.json()["status"] == "denied"
    assert adapter.requests == []


def test_a_dockyard_without_scope_cannot_start_discovery(
    client: TestClient, dockyard_id: int, adapter: StubAdapter
):
    response = start(client, dockyard_id, "127.0.0.1")
    assert response.status_code == 403
    assert adapter.requests == []


def test_excluded_target_is_denied_and_still_recorded(
    client: TestClient, dockyard_id: int, adapter: StubAdapter, add_scope
):
    add_scope(dockyard_id, "127.0.0.0/24")
    add_scope(dockyard_id, "127.0.0.1", rule="exclude")

    assert start(client, dockyard_id, "127.0.0.1").status_code == 403
    runs = client.get(f"/api/dockyards/{dockyard_id}/discoveries").json()
    assert [run["decision"] for run in runs] == ["denied_excluded"]
    assert adapter.requests == []


def test_malformed_target_never_reaches_the_adapter(
    client: TestClient, dockyard_id: int, adapter: StubAdapter, add_scope
):
    add_scope(dockyard_id, "127.0.0.1")
    response = start(client, dockyard_id, "--script=vuln")
    assert response.status_code == 403
    assert response.json()["decision"] == "invalid_target"
    assert adapter.requests == []


def test_unknown_adapter_or_profile_is_rejected(client: TestClient, dockyard_id: int, add_scope):
    add_scope(dockyard_id, "127.0.0.1")
    unknown = client.post(
        f"/api/dockyards/{dockyard_id}/discoveries",
        json={"target": "127.0.0.1", "adapter": "metasploit", "profile": "safe"},
    )
    assert unknown.status_code == 422


def test_allowed_target_runs_and_produces_an_inventory(
    client: TestClient, dockyard_id: int, adapter: StubAdapter, add_scope
):
    add_scope(dockyard_id, "127.0.0.1")
    accepted = start(client, dockyard_id, "127.0.0.1")
    assert accepted.status_code == 202

    run = client.get(
        f"/api/dockyards/{dockyard_id}/discoveries/{accepted.json()['id']}"
    ).json()
    assert run["status"] == "completed"
    assert (run["asset_count"], run["service_count"], run["observation_count"]) == (1, 1, 1)
    assert adapter.requests[0].target.value == "127.0.0.1"

    assets = client.get(f"/api/dockyards/{dockyard_id}/assets").json()
    assert [(asset["identity"], asset["service_count"]) for asset in assets] == [("127.0.0.1", 1)]

    services = client.get(f"/api/dockyards/{dockyard_id}/services").json()
    assert services[0]["port"] == 8080
    # An unidentified service stays unidentified.
    assert services[0]["product"] is None

    observations = client.get(f"/api/dockyards/{dockyard_id}/observations").json()
    assert observations[0]["observation_type"] == "port_state"
    assert observations[0]["discovery_run_id"] == run["id"]
    assert "severity" not in observations[0]


def test_repeated_discovery_updates_instead_of_duplicating(
    client: TestClient, dockyard_id: int, adapter: StubAdapter, add_scope
):
    add_scope(dockyard_id, "127.0.0.1")
    start(client, dockyard_id, "127.0.0.1")
    first = client.get(f"/api/dockyards/{dockyard_id}/assets").json()[0]

    start(client, dockyard_id, "127.0.0.1")
    assets = client.get(f"/api/dockyards/{dockyard_id}/assets").json()
    services = client.get(f"/api/dockyards/{dockyard_id}/services").json()
    observations = client.get(f"/api/dockyards/{dockyard_id}/observations").json()

    assert len(assets) == 1 and len(services) == 1
    assert assets[0]["id"] == first["id"]
    assert assets[0]["first_seen"] == first["first_seen"]
    assert assets[0]["last_seen"] >= first["last_seen"]
    # History is never rewritten: each run keeps its own observations.
    assert len(observations) == 2


def test_a_failing_adapter_marks_the_run_failed(
    client: TestClient, dockyard_id: int, monkeypatch: pytest.MonkeyPatch, add_scope
):
    _install(monkeypatch, StubAdapter(failure=AdapterError("nmap exited with status 2")))
    add_scope(dockyard_id, "127.0.0.1")
    accepted = start(client, dockyard_id, "127.0.0.1")

    run = client.get(
        f"/api/dockyards/{dockyard_id}/discoveries/{accepted.json()['id']}"
    ).json()
    assert run["status"] == "failed"
    assert "status 2" in run["error"]


def test_scope_removed_between_request_and_execution_denies_the_run(
    client: TestClient, dockyard_id: int, monkeypatch: pytest.MonkeyPatch, add_scope
):
    stub = StubAdapter()
    monkeypatch.setattr(registry, "get_adapter", lambda name: stub if name == stub.name else None)
    # Hold the run at pending so the scope can change before it executes.
    monkeypatch.setattr(discovery_runner, "submit_run", lambda run_id: None)
    entry = add_scope(dockyard_id, "127.0.0.1")
    accepted = start(client, dockyard_id, "127.0.0.1")
    assert accepted.status_code == 202

    client.delete(f"/api/dockyards/{dockyard_id}/scope/{entry['id']}")
    discovery_runner.execute_run(accepted.json()["id"])

    run = client.get(
        f"/api/dockyards/{dockyard_id}/discoveries/{accepted.json()['id']}"
    ).json()
    assert run["status"] == "denied"
    assert stub.requests == []


def test_evidence_is_written_and_hashed(
    client: TestClient, dockyard_id: int, adapter: StubAdapter, environment: Path, add_scope
):
    add_scope(dockyard_id, "127.0.0.1")
    accepted = start(client, dockyard_id, "127.0.0.1")
    run_id = accepted.json()["id"]

    records = client.get(f"/api/dockyards/{dockyard_id}/evidence").json()
    kinds = {record["kind"] for record in records}
    assert kinds == {"raw", "normalized", "metadata"}

    run_directory = environment / "evidence" / str(dockyard_id) / str(run_id)
    for record in records:
        stored = run_directory / record["relative_path"]
        assert stored.exists()
        assert sha256(stored.read_bytes()).hexdigest() == record["sha256"]

    metadata = json.loads((run_directory / "metadata.json").read_text())
    assert metadata["adapter"] == {"name": "stub", "version": "9.9.9", "tool_version": "stub 1.0"}
    assert metadata["dockguard"]["decision"] == "allowed"
    assert metadata["invocation"] == ["stub", "127.0.0.1"]
    assert metadata["counts"] == {"assets": 1, "services": 1, "observations": 1}


def test_interrupted_runs_are_marked_rather_than_left_active(
    client: TestClient,
    dockyard_id: int,
    adapter: StubAdapter,
    monkeypatch: pytest.MonkeyPatch,
    add_scope,
):
    monkeypatch.setattr(discovery_runner, "submit_run", lambda run_id: None)
    add_scope(dockyard_id, "127.0.0.1")
    accepted = start(client, dockyard_id, "127.0.0.1")

    import app.database

    with app.database.SessionLocal() as session:
        assert discovery_runner.recover_interrupted_runs(session) == 1

    run = client.get(
        f"/api/dockyards/{dockyard_id}/discoveries/{accepted.json()['id']}"
    ).json()
    assert run["status"] == "failed"
    assert "restart" in run["error"]
