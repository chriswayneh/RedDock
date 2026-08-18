"""Phase 1 only adds tables, so an existing Phase 0 database upgrades in place."""

import sqlite3
from pathlib import Path

import pytest

PHASE_0_SCHEMA = """
CREATE TABLE dockyards (
    id INTEGER NOT NULL PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    description TEXT,
    status VARCHAR(24) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO dockyards (name, description, status)
VALUES ('Existing engagement', 'From 0.1.0', 'draft');
"""


@pytest.fixture()
def phase_0_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    database = tmp_path / "reddock.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(PHASE_0_SCHEMA)
    monkeypatch.setenv("REDDOCK_DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("REDDOCK_EVIDENCE_DIR", str(tmp_path / "evidence"))
    import app.config

    app.config.get_settings.cache_clear()
    import app.database

    app.database.configure_engine()
    yield database
    app.config.get_settings.cache_clear()


def test_phase_0_data_survives_the_phase_1_schema_upgrade(phase_0_database: Path):
    from fastapi.testclient import TestClient

    import app.database
    import app.main

    app.database.initialize_database()
    with TestClient(app.main.app) as client:
        dockyards = client.get("/api/dockyards").json()
        assert [dockyard["name"] for dockyard in dockyards] == ["Existing engagement"]

        # The Phase 1 tables now exist alongside the Phase 0 data.
        assert client.get(f"/api/dockyards/{dockyards[0]['id']}/scope").json() == []
        assert client.get(f"/api/dockyards/{dockyards[0]['id']}/assets").json() == []
        assert client.get(f"/api/dockyards/{dockyards[0]['id']}/discoveries").json() == []


def test_every_phase_1_table_is_created(phase_0_database: Path):
    import app.database

    app.database.initialize_database()
    with sqlite3.connect(phase_0_database) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in rows}
    assert {
        "dockyards",
        "scope_entries",
        "assets",
        "services",
        "observations",
        "discovery_runs",
        "evidence_records",
    } <= tables
