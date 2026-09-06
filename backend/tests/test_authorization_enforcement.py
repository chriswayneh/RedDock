from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.authorization import AuthorizationContext, Role
from app.authorization_dependencies import current_authorization


@pytest.fixture()
def viewer_client(client: TestClient, dockyard_id: int) -> Iterator[TestClient]:
    from app.main import app

    app.dependency_overrides[current_authorization] = lambda: AuthorizationContext(
        organization_id=1,
        user_id=2,
        membership_id=2,
        role=Role.VIEWER,
    )
    yield client
    app.dependency_overrides.pop(current_authorization, None)


def test_public_health_and_version_do_not_require_an_authenticated_principal(client: TestClient):
    from app.main import app

    app.dependency_overrides[current_authorization] = lambda: None
    try:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/ready").status_code == 200
        assert client.get("/api/version").status_code == 200
        denied = client.get("/api/dockyards")
        assert denied.status_code == 401
        assert denied.json() == {"detail": "Authentication required"}
    finally:
        app.dependency_overrides.pop(current_authorization, None)


def test_viewer_can_read_summaries_but_cannot_create_a_dockyard(viewer_client: TestClient):
    assert viewer_client.get("/api/dockyards").status_code == 200
    denied = viewer_client.post("/api/dockyards", json={"name": "Denied"})
    assert denied.status_code == 403
    assert denied.json() == {"detail": "Permission denied"}


def test_viewer_cannot_read_raw_evidence(viewer_client: TestClient, dockyard_id: int):
    denied = viewer_client.get(f"/api/dockyards/{dockyard_id}/evidence")
    assert denied.status_code == 403
    assert denied.json() == {"detail": "Permission denied"}


def test_viewer_cannot_approve_model_disclosure(viewer_client: TestClient, dockyard_id: int):
    denied = viewer_client.post(
        f"/api/dockyards/{dockyard_id}/intelligence/1/approve",
        json={"note": "Should remain blocked"},
    )
    assert denied.status_code == 403
    assert denied.json() == {"detail": "Permission denied"}


def test_viewer_cannot_download_a_dockpack(viewer_client: TestClient, dockyard_id: int):
    denied = viewer_client.get(f"/api/dockyards/{dockyard_id}/reports/1/dockpack")
    assert denied.status_code == 403
    assert denied.json() == {"detail": "Permission denied"}
