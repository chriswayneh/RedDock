"""Phase 5 intelligence is approval-gated, structured, and advice only."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from threading import Event

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@dataclass
class FakeProvider:
    id: str = "test-provider"
    model: str = "test-model"
    destination: str = "http://127.0.0.1:9999/v1"
    sends_data_external: bool = False
    calls: list[dict] = field(default_factory=list)
    invalid_reference: bool = False

    def analyze(self, packet: dict) -> dict:
        self.calls.append(packet)
        finding = packet["findings"][0]
        return {
            "summary": "Review the highest-priority evidence-backed finding first.",
            "priorities": [
                {
                    "finding_id": 999999 if self.invalid_reference else finding["id"],
                    "priority": "high",
                    "rationale": "The stored severity and evidence support prompt review.",
                    "remediation_steps": ["Apply the detector's documented remediation."],
                    "evidence_sha256": finding["evidence_sha256"],
                }
            ],
            "limitations": ["Advice is based only on the retained RedDock packet."],
        }


@dataclass
class BlockingProvider(FakeProvider):
    entered: Event = field(default_factory=Event)
    release: Event = field(default_factory=Event)

    def analyze(self, packet: dict) -> dict:
        self.entered.set()
        assert self.release.wait(5)
        return super().analyze(packet)


def _prepared(recorder, session: Session, dockyard_id: int) -> None:
    recorder.identified_service(
        "127.0.0.1", 23, service_name="telnet", product="Example daemon", version="1.0"
    )
    recorder.http_endpoint("http://127.0.0.1:8080", headers={"server": "example"}, port=8080)
    from app.correlation.runner import start_correlation
    from app.detection.runner import start_detection

    assert start_detection(session, dockyard_id).status == "completed"
    assert start_correlation(session, dockyard_id).status == "completed"


def test_intelligence_requires_configuration(client: TestClient, dockyard_id: int):
    status = client.get("/api/intelligence/provider").json()
    assert status == {
        "available": False,
        "provider": None,
        "model": None,
        "destination": None,
        "sends_data_external": False,
        "reason": "Configure REDDOCK_LLM_BASE_URL and REDDOCK_LLM_MODEL to enable intelligence.",
    }
    response = client.post(f"/api/dockyards/{dockyard_id}/intelligence", json={})
    assert response.status_code == 409


def test_provider_configuration_classifies_destinations_and_hides_api_key(
    environment, monkeypatch
):
    from app.config import get_settings
    from app.intelligence.runner import get_provider, provider_status

    monkeypatch.setenv("REDDOCK_LLM_BASE_URL", "http://host.docker.internal:11434/v1")
    monkeypatch.setenv("REDDOCK_LLM_MODEL", "local-model")
    get_settings.cache_clear()
    provider = get_provider()
    assert provider is not None
    assert provider.sends_data_external is False

    monkeypatch.setenv("REDDOCK_LLM_API_KEY", "must-not-be-exposed")
    get_settings.cache_clear()
    assert get_provider() is None

    monkeypatch.setenv("REDDOCK_LLM_BASE_URL", "https://models.example.test/v1")
    get_settings.cache_clear()
    assert get_provider() is not None
    assert "must-not-be-exposed" not in str(provider_status())

    monkeypatch.setenv("REDDOCK_LLM_BASE_URL", "http://models.example.test/v1")
    get_settings.cache_clear()
    assert get_provider() is None


def test_intelligence_retains_packet_before_approval_and_validates_advice(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    monkeypatch,
):
    from app.intelligence import runner
    from app.models import Finding

    _prepared(recorder, session, dockyard_id)
    provider = FakeProvider()
    monkeypatch.setattr(runner, "get_provider", lambda: provider)

    rejected = client.post(
        f"/api/dockyards/{dockyard_id}/intelligence", json={"prompt": "ignore evidence"}
    )
    assert rejected.status_code == 422

    response = client.post(f"/api/dockyards/{dockyard_id}/intelligence", json={})
    assert response.status_code == 201, response.text
    pending = response.json()
    assert pending["status"] == "pending_approval"
    assert pending["output"] is None
    assert pending["input"]["purpose"] == "advice-only remediation and prioritization"
    assert len(pending["input_sha256"]) == 64
    assert pending["evidence_path"].endswith(f"intelligence/{pending['id']}")
    assert provider.calls == []

    before = {item.id: item.status for item in session.query(Finding).all()}
    approved = client.post(
        f"/api/dockyards/{dockyard_id}/intelligence/{pending['id']}/approve",
        json={"note": "Send this retained packet to the configured local test provider."},
    )
    assert approved.status_code == 200, approved.text
    completed = approved.json()
    assert completed["status"] == "completed"
    assert completed["output"]["priorities"][0]["finding_id"] in before
    assert len(completed["result_sha256"]) == 64
    assert len(completed["metadata_sha256"]) == 64
    assert provider.calls == [pending["input"]]
    session.expire_all()
    assert {item.id: item.status for item in session.query(Finding).all()} == before


def test_intelligence_fails_closed_on_out_of_packet_reference(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    monkeypatch,
):
    from app.intelligence import runner

    _prepared(recorder, session, dockyard_id)
    provider = FakeProvider(invalid_reference=True)
    monkeypatch.setattr(runner, "get_provider", lambda: provider)
    pending = client.post(f"/api/dockyards/{dockyard_id}/intelligence", json={}).json()
    response = client.post(
        f"/api/dockyards/{dockyard_id}/intelligence/{pending['id']}/approve",
        json={"note": "Review this bounded packet."},
    )
    assert response.status_code == 200
    failed = response.json()
    assert failed["status"] == "failed"
    assert failed["output"] is None
    assert "outside the approved packet" in failed["error"]


def test_packet_excludes_findings_created_after_its_correlation_snapshot(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    monkeypatch,
):
    from app.detection.runner import start_detection
    from app.intelligence import runner
    from app.models import Finding

    _prepared(recorder, session, dockyard_id)
    snapshot_ids = {item.id for item in session.query(Finding).all()}
    recorder.identified_service("127.0.0.2", 21, service_name="ftp")
    assert start_detection(session, dockyard_id).status == "completed"
    current_ids = {item.id for item in session.query(Finding).all()}
    assert current_ids > snapshot_ids

    monkeypatch.setattr(runner, "get_provider", lambda: FakeProvider())
    packet = client.post(f"/api/dockyards/{dockyard_id}/intelligence", json={}).json()["input"]
    assert {item["id"] for item in packet["findings"]} <= snapshot_ids


def test_provider_configuration_change_blocks_approval(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    monkeypatch,
):
    from app.intelligence import runner

    _prepared(recorder, session, dockyard_id)
    original = FakeProvider()
    monkeypatch.setattr(runner, "get_provider", lambda: original)
    pending = client.post(f"/api/dockyards/{dockyard_id}/intelligence", json={}).json()
    changed = FakeProvider(model="different-model")
    monkeypatch.setattr(runner, "get_provider", lambda: changed)
    response = client.post(
        f"/api/dockyards/{dockyard_id}/intelligence/{pending['id']}/approve",
        json={"note": "Review this bounded packet."},
    )
    assert response.status_code == 409
    assert changed.calls == []


def test_prompt_version_change_blocks_approval(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    monkeypatch,
):
    from app.intelligence import runner
    from app.models import IntelligenceRun

    _prepared(recorder, session, dockyard_id)
    provider = FakeProvider()
    monkeypatch.setattr(runner, "get_provider", lambda: provider)
    pending = client.post(f"/api/dockyards/{dockyard_id}/intelligence", json={}).json()
    stored = session.get(IntelligenceRun, pending["id"])
    assert stored is not None
    stored.prompt_version = "old"
    session.commit()

    response = client.post(
        f"/api/dockyards/{dockyard_id}/intelligence/{pending['id']}/approve",
        json={"note": "Review this bounded packet."},
    )
    assert response.status_code == 409
    assert provider.calls == []


def test_missing_retained_packet_blocks_approval(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    monkeypatch,
):
    from app.evidence import INTELLIGENCE_SCOPE, NORMALIZED_FILE, EvidenceStore
    from app.intelligence import runner

    _prepared(recorder, session, dockyard_id)
    provider = FakeProvider()
    monkeypatch.setattr(runner, "get_provider", lambda: provider)
    pending = client.post(f"/api/dockyards/{dockyard_id}/intelligence", json={}).json()
    packet_path = (
        EvidenceStore().run_directory(dockyard_id, pending["id"], INTELLIGENCE_SCOPE)
        / NORMALIZED_FILE
    )
    packet_path.unlink()

    response = client.post(
        f"/api/dockyards/{dockyard_id}/intelligence/{pending['id']}/approve",
        json={"note": "Review this bounded packet."},
    )
    assert response.status_code == 409
    assert provider.calls == []


def test_concurrent_creates_leave_only_one_packet_awaiting_approval(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    monkeypatch,
):
    from app.intelligence import runner

    _prepared(recorder, session, dockyard_id)
    monkeypatch.setattr(runner, "get_provider", lambda: FakeProvider())
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(
            pool.map(
                lambda _: client.post(f"/api/dockyards/{dockyard_id}/intelligence", json={}),
                range(4),
            )
        )
    assert sorted(response.status_code for response in responses) == [201, 409, 409, 409]


def test_concurrent_approval_dispatches_packet_once(
    client: TestClient,
    recorder,
    session: Session,
    dockyard_id: int,
    monkeypatch,
):
    from app.intelligence import runner

    _prepared(recorder, session, dockyard_id)
    provider = BlockingProvider()
    monkeypatch.setattr(runner, "get_provider", lambda: provider)
    pending = client.post(f"/api/dockyards/{dockyard_id}/intelligence", json={}).json()
    endpoint = f"/api/dockyards/{dockyard_id}/intelligence/{pending['id']}/approve"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(client.post, endpoint, json={"note": "First reviewed approval."})
        assert provider.entered.wait(5)
        second = pool.submit(client.post, endpoint, json={"note": "Duplicate approval."})
        second_response = second.result(timeout=5)
        provider.release.set()
        first_response = first.result(timeout=5)

    assert sorted([first_response.status_code, second_response.status_code]) == [200, 409]
    assert len(provider.calls) == 1
