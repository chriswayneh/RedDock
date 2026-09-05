"""Security contract for Phase 7's data-only detector extensions."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.config import get_settings
from app.detection.base import DetectionContext, ObservationView
from app.detection.registry import available_detectors, clear_plugin_cache
from app.detector_plugins import PluginConfigurationError, load_declarative_detectors


def manifest(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": "reddock.detector-plugin/1",
        "id": "plugin.example-server",
        "version": "1.0.0",
        "title": "Example server policy",
        "description": "Flags an explicitly identified example product.",
        "rules": [
            {
                "id": "example-product",
                "observation_type": "service_identified",
                "detail_key": "product",
                "equals": "ExampleServer",
                "title": "Example server identified",
                "description": "The service identified itself as ExampleServer.",
                "category": "information_disclosure",
                "severity": "informational",
                "confidence": "medium",
                "remediation": "Review whether this service is expected.",
            }
        ],
    }
    document.update(overrides)
    return document


def write_manifest(directory: Path, document: dict[str, object], name: str = "plugin.json") -> Path:
    path = directory / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def observation(
    observation_id: int,
    value: object,
    *,
    observed_at: datetime | None = None,
) -> ObservationView:
    return ObservationView(
        id=observation_id,
        discovery_run_id=3,
        asset_id=5,
        service_id=7,
        adapter="nmap",
        observation_type="service_identified",
        summary="A service was identified",
        confidence="medium",
        observed_at=observed_at or datetime.now(UTC),
        detail={"product": value},
    )


@pytest.fixture(autouse=True)
def reset_registry(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("REDDOCK_DETECTOR_PLUGIN_DIR", raising=False)
    get_settings.cache_clear()
    clear_plugin_cache()
    yield
    get_settings.cache_clear()
    clear_plugin_cache()


def test_unconfigured_registry_contains_only_reviewed_built_ins():
    detectors = available_detectors()
    assert {item.id for item in detectors} == {
        "http.security_headers",
        "service.rules",
        "tls.certificates",
    }


def test_valid_manifest_loads_with_content_addressed_provenance(tmp_path: Path):
    source = write_manifest(tmp_path, manifest())

    (detector,) = load_declarative_detectors(str(tmp_path))

    assert detector.id == "plugin.example-server"
    assert detector.version.startswith("1.0.0+")
    assert detector.source == "declarative"
    assert detector.execution == "passive"
    assert detector.manifest_sha256
    assert detector.manifest_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert detector.consumes == ("service_identified",)


def test_rule_matches_only_the_latest_observation_for_a_subject(tmp_path: Path):
    write_manifest(tmp_path, manifest())
    (detector,) = load_declarative_detectors(str(tmp_path))
    now = datetime.now(UTC)
    context = DetectionContext(
        dockyard_id=1,
        generated_at=now,
        observations=(
            observation(1, "ExampleServer", observed_at=now - timedelta(minutes=1)),
            observation(2, "OtherServer", observed_at=now),
        ),
    )

    assert detector.detect(context) == ()


def test_rule_emits_a_fixed_evidence_linked_finding(tmp_path: Path):
    write_manifest(tmp_path, manifest())
    (detector,) = load_declarative_detectors(str(tmp_path))
    seen = observation(11, "ExampleServer")

    (finding,) = detector.detect(
        DetectionContext(dockyard_id=1, generated_at=datetime.now(UTC), observations=(seen,))
    )

    assert finding.rule_id == "example-product"
    assert finding.evidence_observation_ids == (11,)
    assert finding.asset_id == 5
    assert finding.service_id == 7
    assert finding.detail["observed"] == "ExampleServer"


def test_json_boolean_does_not_match_an_integer(tmp_path: Path):
    document = manifest()
    document["rules"][0]["equals"] = 1  # type: ignore[index]
    write_manifest(tmp_path, document)
    (detector,) = load_declarative_detectors(str(tmp_path))

    assert detector.detect(
        DetectionContext(
            dockyard_id=1,
            generated_at=datetime.now(UTC),
            observations=(observation(1, True),),
        )
    ) == ()


@pytest.mark.parametrize(
    "change",
    [
        {"id": "built-in-looking"},
        {"module": "untrusted.module"},
        {"command": "whoami"},
        {"url": "https://example.invalid/plugin"},
        {"rules": []},
    ],
)
def test_unsafe_or_out_of_contract_manifest_is_rejected(tmp_path: Path, change: dict):
    write_manifest(tmp_path, manifest(**change))

    with pytest.raises(PluginConfigurationError):
        load_declarative_detectors(str(tmp_path))


def test_duplicate_json_key_is_rejected(tmp_path: Path):
    (tmp_path / "plugin.json").write_text(
        '{"schema":"reddock.detector-plugin/1","schema":"other"}', encoding="utf-8"
    )

    with pytest.raises(PluginConfigurationError, match="Duplicate JSON key"):
        load_declarative_detectors(str(tmp_path))


def test_duplicate_plugin_ids_are_rejected(tmp_path: Path):
    write_manifest(tmp_path, manifest(), "one.json")
    write_manifest(tmp_path, manifest(), "two.json")

    with pytest.raises(PluginConfigurationError, match="IDs must be unique"):
        load_declarative_detectors(str(tmp_path))


def test_registry_fails_closed_on_an_invalid_configured_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    write_manifest(tmp_path, manifest(command="whoami"))
    monkeypatch.setenv("REDDOCK_DETECTOR_PLUGIN_DIR", str(tmp_path))
    get_settings.cache_clear()

    with pytest.raises(PluginConfigurationError):
        available_detectors()


def test_oversized_manifest_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(get_settings(), "max_detector_plugin_bytes", 20)
    write_manifest(tmp_path, manifest())

    with pytest.raises(PluginConfigurationError, match="exceeds"):
        load_declarative_detectors(str(tmp_path))


def test_registry_is_frozen_until_process_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    write_manifest(tmp_path, manifest())
    monkeypatch.setenv("REDDOCK_DETECTOR_PLUGIN_DIR", str(tmp_path))
    get_settings.cache_clear()

    first = available_detectors()
    write_manifest(tmp_path, manifest(id="plugin.changed"))
    second = available_detectors()

    assert [item.id for item in first] == [item.id for item in second]
    assert "plugin.example-server" in {item.id for item in second}


def test_api_publishes_plugin_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client
):
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    write_manifest(plugin_dir, manifest())
    monkeypatch.setenv("REDDOCK_DETECTOR_PLUGIN_DIR", str(plugin_dir))
    get_settings.cache_clear()
    clear_plugin_cache()

    response = client.get("/api/detectors")

    assert response.status_code == 200
    published = {item["id"]: item for item in response.json()}
    assert published["http.security_headers"]["source"] == "built-in"
    plugin = published["plugin.example-server"]
    assert plugin["source"] == "declarative"
    assert plugin["execution"] == "passive"
    assert len(plugin["manifest_sha256"]) == 64
