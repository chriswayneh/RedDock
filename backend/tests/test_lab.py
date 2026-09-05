import pytest

from app.config import get_settings
from app.lab_capabilities import EXTENDED_SERVICE_DISCOVERY, LAB_ACKNOWLEDGEMENT


@pytest.fixture()
def runner_module():
    from app.discovery import runner

    return runner


def _enable_lab(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDDOCK_LAB_MODE_ENABLED", "true")
    get_settings.cache_clear()


def _authorize(client, dockyard_id: int, duration_minutes: int = 60):
    return client.post(
        f"/api/dockyards/{dockyard_id}/lab/authorizations",
        json={
            "capability": EXTENDED_SERVICE_DISCOVERY,
            "acknowledgement": LAB_ACKNOWLEDGEMENT,
            "note": "Owner-approved isolated loopback lab",
            "duration_minutes": duration_minutes,
        },
    )


def test_lab_status_is_disabled_by_default_and_advertises_fixed_boundary(client):
    response = client.get("/api/lab/status")
    assert response.status_code == 200
    body = response.json()
    assert body["deployment_enabled"] is False
    assert body["acknowledgement"] == LAB_ACKNOWLEDGEMENT
    assert body["max_authorization_minutes"] == 120
    assert body["capabilities"] == [
        {
            "id": EXTENDED_SERVICE_DISCOVERY,
            "title": "Extended TCP service discovery",
            "description": (
                "Fixed TCP connect scan of the 1,000 most common ports with bounded "
                "version detection. No scripts, UDP, stealth, credentials, or raw flags."
            ),
            "risk": "lab",
            "single_host_only": True,
        }
    ]


def test_disabled_deployment_refuses_and_audits_authorization(client, dockyard_id):
    response = _authorize(client, dockyard_id)
    assert response.status_code == 403
    assert response.json()["detail"] == "Lab mode is disabled by the deployment owner"

    history = client.get(f"/api/dockyards/{dockyard_id}/lab/authorizations").json()
    assert len(history) == 1
    assert history[0]["status"] == "denied"
    audit = client.get(f"/api/dockyards/{dockyard_id}/lab/audit").json()
    assert [(event["action"], event["decision"]) for event in audit] == [
        ("authorize", "denied")
    ]


def test_authorization_requires_exact_acknowledgement(client, dockyard_id, monkeypatch):
    _enable_lab(monkeypatch)
    response = client.post(
        f"/api/dockyards/{dockyard_id}/lab/authorizations",
        json={
            "capability": EXTENDED_SERVICE_DISCOVERY,
            "acknowledgement": "yes",
            "note": "Authorized lab",
        },
    )
    assert response.status_code == 422
    assert client.get(f"/api/dockyards/{dockyard_id}/lab/authorizations").json() == []


def test_authorization_can_be_revoked_and_extra_revoke_input_is_rejected(
    client, dockyard_id, monkeypatch
):
    _enable_lab(monkeypatch)
    created = _authorize(client, dockyard_id, duration_minutes=5)
    assert created.status_code == 201
    authorization = created.json()
    assert authorization["status"] == "active"

    path = f"/api/dockyards/{dockyard_id}/lab/authorizations/{authorization['id']}/revoke"
    assert client.post(path, json={"unexpected": True}).status_code == 422
    revoked = client.post(path, json={})
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    audit = client.get(f"/api/dockyards/{dockyard_id}/lab/audit").json()
    assert [(event["action"], event["decision"]) for event in reversed(audit)] == [
        ("authorize", "allowed"),
        ("revoke", "allowed"),
    ]


def test_new_authorization_supersedes_the_previous_grant(client, dockyard_id, monkeypatch):
    _enable_lab(monkeypatch)
    first = _authorize(client, dockyard_id).json()
    second = _authorize(client, dockyard_id).json()
    assert second["id"] > first["id"]

    history = client.get(f"/api/dockyards/{dockyard_id}/lab/authorizations").json()
    assert [(item["id"], item["status"]) for item in history] == [
        (second["id"], "active"),
        (first["id"], "superseded"),
    ]


def test_lab_discovery_needs_both_gates_and_denial_is_a_run(
    client, dockyard_id, add_scope, monkeypatch, runner_module
):
    add_scope(dockyard_id, "127.0.0.1")
    submitted: list[int] = []
    monkeypatch.setattr(runner_module, "submit_run", submitted.append)

    denied = client.post(
        f"/api/dockyards/{dockyard_id}/discoveries",
        json={
            "target": "127.0.0.1",
            "adapter": "nmap",
            "profile": "lab_extended_service_discovery",
        },
    )
    assert denied.status_code == 403
    assert denied.json()["decision"] == "denied_policy"
    assert submitted == []

    _enable_lab(monkeypatch)
    still_denied = client.post(
        f"/api/dockyards/{dockyard_id}/discoveries",
        json={
            "target": "127.0.0.1",
            "adapter": "nmap",
            "profile": "lab_extended_service_discovery",
        },
    )
    assert still_denied.status_code == 403
    assert "No active" in still_denied.json()["decision_reason"]

    assert _authorize(client, dockyard_id).status_code == 201
    allowed = client.post(
        f"/api/dockyards/{dockyard_id}/discoveries",
        json={
            "target": "127.0.0.1",
            "adapter": "nmap",
            "profile": "lab_extended_service_discovery",
        },
    )
    assert allowed.status_code == 202
    assert submitted == [allowed.json()["id"]]


def test_lab_profile_refuses_network_targets_even_when_authorized(
    client, dockyard_id, add_scope, monkeypatch
):
    _enable_lab(monkeypatch)
    add_scope(dockyard_id, "192.0.2.0/24")
    assert _authorize(client, dockyard_id).status_code == 201
    response = client.post(
        f"/api/dockyards/{dockyard_id}/discoveries",
        json={
            "target": "192.0.2.0/24",
            "adapter": "nmap",
            "profile": "lab_extended_service_discovery",
        },
    )
    assert response.status_code == 403
    assert response.json()["status"] == "denied"
    assert "limited to one host" in response.json()["decision_reason"]
    event = client.get(f"/api/dockyards/{dockyard_id}/lab/audit").json()[0]
    assert (event["action"], event["decision"]) == ("request", "denied")
    assert event["discovery_run_id"] == response.json()["id"]


def test_lab_profile_refuses_a_name_resolving_to_multiple_hosts(
    client, dockyard_id, add_scope, monkeypatch, runner_module
):
    _enable_lab(monkeypatch)
    add_scope(dockyard_id, "app.lab.local")
    assert _authorize(client, dockyard_id).status_code == 201
    monkeypatch.setattr(
        runner_module,
        "system_resolver",
        lambda _hostname: ("192.0.2.10", "192.0.2.11"),
    )

    response = client.post(
        f"/api/dockyards/{dockyard_id}/discoveries",
        json={
            "target": "app.lab.local",
            "adapter": "nmap",
            "profile": "lab_extended_service_discovery",
        },
    )

    assert response.status_code == 403
    assert "resolved to 2 addresses" in response.json()["decision_reason"]
    event = client.get(f"/api/dockyards/{dockyard_id}/lab/audit").json()[0]
    assert event["decision"] == "denied"
    assert event["discovery_run_id"] == response.json()["id"]


def test_lab_saturation_denial_is_retained(
    client, dockyard_id, add_scope, monkeypatch, runner_module
):
    _enable_lab(monkeypatch)
    add_scope(dockyard_id, "127.0.0.1")
    assert _authorize(client, dockyard_id).status_code == 201
    monkeypatch.setattr(
        runner_module,
        "active_run_count",
        lambda _session: get_settings().max_concurrent_runs,
    )

    response = client.post(
        f"/api/dockyards/{dockyard_id}/discoveries",
        json={
            "target": "127.0.0.1",
            "adapter": "nmap",
            "profile": "lab_extended_service_discovery",
        },
    )

    assert response.status_code == 403
    assert "in flight" in response.json()["decision_reason"]
    event = client.get(f"/api/dockyards/{dockyard_id}/lab/audit").json()[0]
    assert event["decision"] == "denied"
    assert event["discovery_run_id"] == response.json()["id"]


def test_execution_refuses_when_a_name_changes_to_multiple_hosts(
    client, dockyard_id, add_scope, monkeypatch, runner_module
):
    from app.discovery.nmap import NmapAdapter

    _enable_lab(monkeypatch)
    add_scope(dockyard_id, "app.lab.local")
    assert _authorize(client, dockyard_id).status_code == 201
    resolutions = iter(
        (("192.0.2.10",), ("192.0.2.10", "192.0.2.11"))
    )
    monkeypatch.setattr(runner_module, "system_resolver", lambda _hostname: next(resolutions))
    monkeypatch.setattr(runner_module, "submit_run", lambda _run_id: None)
    created = client.post(
        f"/api/dockyards/{dockyard_id}/discoveries",
        json={
            "target": "app.lab.local",
            "adapter": "nmap",
            "profile": "lab_extended_service_discovery",
        },
    ).json()

    def should_not_run(*_args, **_kwargs):
        raise AssertionError("multi-address lab target reached the adapter")

    monkeypatch.setattr(NmapAdapter, "run", should_not_run)
    runner_module.execute_run(created["id"])

    run = client.get(f"/api/dockyards/{dockyard_id}/discoveries/{created['id']}").json()
    assert run["status"] == "denied"
    assert "resolved to 2 addresses" in run["decision_reason"]
    event = next(
        item
        for item in client.get(f"/api/dockyards/{dockyard_id}/lab/audit").json()
        if item["action"] == "execute"
    )
    assert event["decision"] == "denied"
    assert event["discovery_run_id"] == created["id"]


def test_execution_rechecks_revocation_before_adapter_runs(
    client, dockyard_id, add_scope, monkeypatch, runner_module
):
    from app.discovery.nmap import NmapAdapter

    _enable_lab(monkeypatch)
    add_scope(dockyard_id, "127.0.0.1")
    authorization = _authorize(client, dockyard_id).json()
    submitted: list[int] = []
    monkeypatch.setattr(runner_module, "submit_run", submitted.append)
    created = client.post(
        f"/api/dockyards/{dockyard_id}/discoveries",
        json={
            "target": "127.0.0.1",
            "adapter": "nmap",
            "profile": "lab_extended_service_discovery",
        },
    ).json()

    client.post(
        f"/api/dockyards/{dockyard_id}/lab/authorizations/{authorization['id']}/revoke",
        json={},
    )

    def should_not_run(*_args, **_kwargs):
        raise AssertionError("revoked lab capability reached the adapter")

    monkeypatch.setattr(NmapAdapter, "run", should_not_run)
    runner_module.execute_run(created["id"])
    run = client.get(f"/api/dockyards/{dockyard_id}/discoveries/{created['id']}").json()
    assert run["status"] == "denied"
    assert run["decision"] == "denied_policy"

    events = client.get(f"/api/dockyards/{dockyard_id}/lab/audit").json()
    execute = next(event for event in events if event["action"] == "execute")
    assert execute["decision"] == "denied"
    assert execute["discovery_run_id"] == created["id"]
