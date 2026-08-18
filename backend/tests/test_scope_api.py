from fastapi.testclient import TestClient


def test_scope_entries_are_stored_normalized(client: TestClient, dockyard_id: int):
    created = client.post(
        f"/api/dockyards/{dockyard_id}/scope",
        json={"rule": "include", "target": " APP.Lab.Local. ", "note": "staging web"},
    )
    assert created.status_code == 201
    assert created.json()["value"] == "app.lab.local"
    assert created.json()["kind"] == "hostname"

    listed = client.get(f"/api/dockyards/{dockyard_id}/scope").json()
    assert [entry["value"] for entry in listed] == ["app.lab.local"]


def test_broad_and_malformed_scope_entries_are_refused(client: TestClient, dockyard_id: int):
    for target in ["0.0.0.0/0", "10.0.0.0/8", "--script=vuln", "192.168.1.999"]:
        response = client.post(
            f"/api/dockyards/{dockyard_id}/scope", json={"target": target}
        )
        assert response.status_code == 422, target


def test_duplicate_scope_entries_are_refused(client: TestClient, dockyard_id: int, add_scope):
    add_scope(dockyard_id, "192.168.1.0/24")
    duplicate = client.post(
        f"/api/dockyards/{dockyard_id}/scope", json={"target": "192.168.1.37/24"}
    )
    assert duplicate.status_code == 422
    assert "already" in duplicate.json()["detail"]


def test_scope_entries_can_be_removed(client: TestClient, dockyard_id: int, add_scope):
    entry = add_scope(dockyard_id, "192.168.1.10")
    assert client.delete(f"/api/dockyards/{dockyard_id}/scope/{entry['id']}").status_code == 204
    assert client.get(f"/api/dockyards/{dockyard_id}/scope").json() == []
    assert client.delete(f"/api/dockyards/{dockyard_id}/scope/{entry['id']}").status_code == 404


def test_evaluate_explains_both_outcomes(client: TestClient, dockyard_id: int, add_scope):
    add_scope(dockyard_id, "192.168.1.0/24")
    add_scope(dockyard_id, "192.168.1.10", rule="exclude")

    allowed = client.post(
        f"/api/dockyards/{dockyard_id}/scope/evaluate", json={"target": "192.168.1.42"}
    ).json()
    assert allowed["allowed"] is True
    assert allowed["matched_rule"] == "192.168.1.0/24"

    denied = client.post(
        f"/api/dockyards/{dockyard_id}/scope/evaluate", json={"target": "192.168.1.10"}
    ).json()
    assert denied["decision"] == "denied_excluded"
    assert "exclusion" in denied["reason"]


def test_scope_endpoints_require_a_real_dockyard(client: TestClient):
    assert client.get("/api/dockyards/999/scope").status_code == 404
    assert (
        client.post("/api/dockyards/999/scope/evaluate", json={"target": "127.0.0.1"}).status_code
        == 404
    )
