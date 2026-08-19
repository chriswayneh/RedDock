import json
import tomllib
from pathlib import Path

import pytest

from app.config import get_settings

BACKEND = Path(__file__).resolve().parents[1]


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "reddock-core"}


def test_version_endpoint(client):
    response = client.get("/api/version")
    assert response.status_code == 200
    assert response.json()["name"] == "RedDock"
    assert response.json()["version"] == get_settings().version


def test_create_list_and_retrieve_dockyard(client):
    created = client.post(
        "/api/dockyards", json={"name": "Internal review", "description": "Authorized lab"}
    )
    assert created.status_code == 201
    dockyard = created.json()
    assert dockyard["status"] == "draft"

    listed = client.get("/api/dockyards")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [dockyard["id"]]

    retrieved = client.get(f"/api/dockyards/{dockyard['id']}")
    assert retrieved.status_code == 200
    assert retrieved.json()["name"] == "Internal review"


def test_invalid_dockyard_request_is_rejected(client):
    response = client.post("/api/dockyards", json={"name": "   "})
    assert response.status_code == 422


def test_unknown_dockyard_fields_are_rejected(client):
    response = client.post("/api/dockyards", json={"name": "Lab", "unexpected": "value"})
    assert response.status_code == 422


def test_missing_dockyard_returns_404(client):
    response = client.get("/api/dockyards/999")
    assert response.status_code == 404


def test_dockyard_is_persisted_for_a_new_client(client):
    client.post("/api/dockyards", json={"name": "Persistent dockyard"})
    assert client.get("/api/dockyards").json()[0]["name"] == "Persistent dockyard"


def test_version_reports_the_current_phase(client):
    assert client.get("/api/version").json()["phase"].startswith("Phase 2")


def test_the_application_and_both_packages_report_one_version(client):
    """A release aligns the application, the API and the packages, or it is not one."""
    reported = client.get("/api/version").json()["version"]
    backend = tomllib.loads(BACKEND.joinpath("pyproject.toml").read_bytes().decode())
    assert reported == backend["project"]["version"]

    package = BACKEND.parent / "frontend" / "package.json"
    if not package.exists():  # the backend test image mounts backend/ alone
        pytest.skip("The frontend package is not present in this checkout")
    assert reported == json.loads(package.read_text(encoding="utf-8"))["version"]


def test_detectors_are_advertised_without_an_offensive_capability(client):
    detectors = client.get("/api/detectors").json()
    assert detectors
    for detector in detectors:
        assert detector["id"] and detector["version"] and detector["consumes"]
        assert not {"exploit", "attack", "bruteforce"} & set(detector["id"].split("."))


def test_adapters_are_advertised_with_their_safe_profiles(client):
    adapters = client.get("/api/adapters").json()
    assert response_names(adapters) == {"nmap", "http"}

    nmap = next(item for item in adapters if item["name"] == "nmap")
    assert {profile["name"] for profile in nmap["profiles"]} == {
        "host_discovery",
        "service_discovery",
    }
    # No adapter advertises an aggressive or exploitation profile.
    for adapter in adapters:
        for profile in adapter["profiles"]:
            assert profile["name"] not in {"aggressive", "stealth", "attack", "exploit"}


def response_names(adapters) -> set[str]:
    return {adapter["name"] for adapter in adapters}
