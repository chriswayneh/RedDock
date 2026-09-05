import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point RedDock at a throwaway database and evidence root."""
    monkeypatch.setenv("REDDOCK_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("REDDOCK_EVIDENCE_DIR", str(tmp_path / "evidence"))
    for name in (
        "REDDOCK_LLM_BASE_URL",
        "REDDOCK_LLM_MODEL",
        "REDDOCK_LLM_API_KEY",
        "REDDOCK_LAB_MODE_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)
    # Modules read settings at import time; isolate after changing the environment.
    import app.config

    app.config.get_settings.cache_clear()
    import app.database

    app.database.configure_engine()
    yield tmp_path
    os.environ.pop("REDDOCK_DATABASE_URL", None)
    os.environ.pop("REDDOCK_EVIDENCE_DIR", None)
    app.config.get_settings.cache_clear()


@pytest.fixture()
def client(environment: Path) -> Iterator[TestClient]:
    import app.main

    with TestClient(app.main.app) as test_client:
        yield test_client


@pytest.fixture()
def session(environment: Path) -> Iterator[Session]:
    import app.database

    app.database.initialize_database()
    with app.database.SessionLocal() as db_session:
        yield db_session


@pytest.fixture()
def dockyard_id(client: TestClient) -> int:
    response = client.post("/api/dockyards", json={"name": "Authorized lab"})
    assert response.status_code == 201
    return response.json()["id"]


@pytest.fixture()
def add_scope(client: TestClient):
    """Add one authorized scope entry through the API."""

    def _add(dockyard: int, target: str, rule: str = "include") -> dict:
        response = client.post(
            f"/api/dockyards/{dockyard}/scope", json={"rule": rule, "target": target}
        )
        assert response.status_code == 201, response.text
        return response.json()

    return _add


@pytest.fixture()
def recorder(dockyard_id: int):
    """Record Phase 1 state for a Dockyard so detection has something to read."""
    import app.database
    from tests.phase1 import Recorder

    with app.database.SessionLocal() as db_session:
        yield Recorder(db_session, dockyard_id)
