import subprocess
from pathlib import Path

import pytest

from app.discovery.base import AdapterError, AdapterRequest
from app.discovery.nmap import (
    HOST_DISCOVERY,
    LAB_EXTENDED_SERVICE_DISCOVERY,
    SERVICE_DISCOVERY,
    NmapAdapter,
)
from app.targets import normalize_target

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_service_discovery.xml"


def request(target: str = "127.0.0.1", profile: str = SERVICE_DISCOVERY, **kwargs):
    return AdapterRequest(target=normalize_target(target), profile=profile, **kwargs)


def test_service_discovery_arguments_are_safe_and_explicit():
    arguments = NmapAdapter().prepare(request())
    assert arguments[1:] == [
        "-n",
        "-oX",
        "-",
        "-T3",
        "--max-retries",
        "2",
        "--host-timeout",
        "120s",
        "-Pn",
        "-sT",
        "--top-ports",
        "100",
        "-sV",
        "--version-intensity",
        "2",
        "127.0.0.1",
    ]


def test_no_aggressive_or_scripting_options_are_ever_generated():
    adapter = NmapAdapter()
    generated = (
        set(adapter.prepare(request()))
        | set(adapter.prepare(request(profile=HOST_DISCOVERY)))
        | set(adapter.prepare(request(profile=LAB_EXTENDED_SERVICE_DISCOVERY)))
    )
    forbidden = {"-A", "--script", "-sU", "-f", "-D", "--source-port", "-O", "--spoof-mac"}
    assert not generated & forbidden
    assert not any(argument.startswith("--script") for argument in generated)


def test_lab_service_discovery_is_fixed_and_bounded():
    arguments = NmapAdapter().prepare(request(profile=LAB_EXTENDED_SERVICE_DISCOVERY))
    assert arguments[arguments.index("--top-ports") + 1] == "1000"
    assert arguments[arguments.index("--version-intensity") + 1] == "5"
    assert "-sT" in arguments
    assert "-sV" in arguments


def test_host_discovery_does_not_scan_ports():
    arguments = NmapAdapter().prepare(request(profile=HOST_DISCOVERY))
    assert "-sn" in arguments
    assert "--top-ports" not in arguments


def test_exclusions_are_passed_through_as_a_structured_option():
    arguments = NmapAdapter().prepare(
        request("192.168.1.0/24", excluded_addresses=("192.168.1.1", "192.168.1.10"))
    )
    assert arguments[arguments.index("--exclude") + 1] == "192.168.1.1,192.168.1.10"


def test_a_named_target_is_scanned_by_its_resolved_address():
    arguments = NmapAdapter().prepare(
        request("app.lab.local", resolved_addresses=("192.168.1.10",))
    )
    assert arguments[-1] == "192.168.1.10"
    assert "app.lab.local" not in arguments


def test_a_named_target_without_resolution_never_reaches_nmap():
    with pytest.raises(AdapterError):
        NmapAdapter().prepare(request("app.lab.local"))


def test_unknown_profile_is_refused():
    with pytest.raises(AdapterError):
        NmapAdapter().prepare(request(profile="aggressive"))


def test_fixture_output_normalizes_into_assets_services_and_observations():
    adapter = NmapAdapter()
    document = adapter.parse(FIXTURE.read_bytes())
    assets, observations = adapter.normalize(document, request())

    assert len(assets) == 1
    asset = assets[0]
    assert (asset.identity, asset.ip_address) == ("127.0.0.1", "127.0.0.1")
    # The filtered port is not persisted as a service; the down host is skipped.
    assert sorted(service.port for service in asset.services) == [22, 8080]

    ssh = next(service for service in asset.services if service.port == 22)
    http = next(service for service in asset.services if service.port == 8080)
    # A port-table guess is not evidence: only the probed service is identified.
    assert (ssh.service_name, ssh.product, ssh.version) == (None, None, None)
    assert (http.service_name, http.product, http.version) == ("http", "uvicorn", "0.34.0")

    types = [observation.observation_type for observation in observations]
    assert types.count("host_responded") == 1
    assert types.count("port_state") == 2
    assert types.count("service_identified") == 1


def test_broken_xml_fails_the_run_rather_than_producing_results():
    with pytest.raises(AdapterError, match="could not be parsed"):
        NmapAdapter().parse(b"<nmaprun><host>")


def test_a_missing_binary_is_reported_clearly(monkeypatch: pytest.MonkeyPatch):
    def missing(*_args, **_kwargs):
        raise FileNotFoundError("nmap")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(AdapterError, match="not available"):
        NmapAdapter().execute(["nmap", "-sn", "127.0.0.1"], 30)


def test_a_timeout_is_reported_as_the_run_limit(monkeypatch: pytest.MonkeyPatch):
    def slow(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=30)

    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(AdapterError, match="30s run limit"):
        NmapAdapter().execute(["nmap", "-sn", "127.0.0.1"], 30)


def test_a_failing_tool_run_surfaces_its_exit_status(monkeypatch: pytest.MonkeyPatch):
    def failing(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=[], returncode=2, stdout=b"", stderr=b"QUITTING! bad option"
        )

    monkeypatch.setattr(subprocess, "run", failing)
    with pytest.raises(AdapterError, match="exited with status 2"):
        NmapAdapter().execute(["nmap", "-sn", "127.0.0.1"], 30)


def test_execution_never_uses_a_shell(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    def record(arguments, **kwargs):
        captured.update(kwargs)
        captured["arguments"] = arguments
        return subprocess.CompletedProcess(args=arguments, returncode=0, stdout=b"<nmaprun/>")

    monkeypatch.setattr(subprocess, "run", record)
    NmapAdapter().execute(["nmap", "-sn", "127.0.0.1"], 30)
    assert captured["shell"] is False
    assert captured["timeout"] == 30
    assert isinstance(captured["arguments"], list)
