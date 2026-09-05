"""Every phase so far only adds tables, so a deployed database upgrades in place.

Each phase records the schema of the release before it as literal DDL and proves
that a database built from it survives `create_all` with its data intact and the
new phase working on top. That is the check that keeps "purely additive" a fact
rather than an intention.
"""

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
    with TestClient(app.main.app, base_url="http://localhost") as client:
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
    with sqlite3.connect(phase_0_database) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0001_v080",
        )


#: The schema as released in v0.2.1, written out rather than derived, so a
#: change to the current models cannot quietly change what this test compares
#: against.
PHASE_1_SCHEMA = """
CREATE TABLE dockyards (
    id INTEGER NOT NULL PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    description TEXT,
    status VARCHAR(24) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);
CREATE TABLE scope_entries (
    id INTEGER NOT NULL PRIMARY KEY,
    dockyard_id INTEGER NOT NULL,
    rule VARCHAR(16) NOT NULL,
    kind VARCHAR(16) NOT NULL,
    value VARCHAR(255) NOT NULL,
    note VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_scope_entry UNIQUE (dockyard_id, rule, value),
    FOREIGN KEY(dockyard_id) REFERENCES dockyards (id) ON DELETE CASCADE
);
CREATE TABLE assets (
    id INTEGER NOT NULL PRIMARY KEY,
    dockyard_id INTEGER NOT NULL,
    asset_type VARCHAR(16) NOT NULL,
    identity VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    hostname VARCHAR(253),
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_asset_identity UNIQUE (dockyard_id, asset_type, identity),
    FOREIGN KEY(dockyard_id) REFERENCES dockyards (id) ON DELETE CASCADE
);
CREATE TABLE services (
    id INTEGER NOT NULL PRIMARY KEY,
    asset_id INTEGER NOT NULL,
    transport VARCHAR(8) NOT NULL,
    port INTEGER NOT NULL,
    state VARCHAR(16) NOT NULL,
    service_name VARCHAR(64),
    product VARCHAR(128),
    version VARCHAR(64),
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    CONSTRAINT uq_service_socket UNIQUE (asset_id, transport, port),
    FOREIGN KEY(asset_id) REFERENCES assets (id) ON DELETE CASCADE
);
CREATE TABLE discovery_runs (
    id INTEGER NOT NULL PRIMARY KEY,
    dockyard_id INTEGER NOT NULL,
    adapter VARCHAR(32) NOT NULL,
    adapter_version VARCHAR(32) NOT NULL,
    profile VARCHAR(32) NOT NULL,
    requested_target VARCHAR(255) NOT NULL,
    normalized_target VARCHAR(255),
    status VARCHAR(16) NOT NULL,
    decision VARCHAR(32) NOT NULL,
    decision_reason VARCHAR(500) NOT NULL,
    error VARCHAR(500),
    asset_count INTEGER NOT NULL,
    service_count INTEGER NOT NULL,
    observation_count INTEGER NOT NULL,
    evidence_path VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    started_at DATETIME,
    completed_at DATETIME,
    FOREIGN KEY(dockyard_id) REFERENCES dockyards (id) ON DELETE CASCADE
);
CREATE TABLE observations (
    id INTEGER NOT NULL PRIMARY KEY,
    dockyard_id INTEGER NOT NULL,
    discovery_run_id INTEGER,
    asset_id INTEGER,
    service_id INTEGER,
    adapter VARCHAR(32) NOT NULL,
    observation_type VARCHAR(32) NOT NULL,
    summary VARCHAR(500) NOT NULL,
    detail JSON,
    confidence VARCHAR(16) NOT NULL,
    raw_reference VARCHAR(255),
    observed_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY(dockyard_id) REFERENCES dockyards (id) ON DELETE CASCADE,
    FOREIGN KEY(discovery_run_id) REFERENCES discovery_runs (id) ON DELETE SET NULL,
    FOREIGN KEY(asset_id) REFERENCES assets (id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services (id) ON DELETE CASCADE
);
CREATE INDEX ix_observation_dockyard_time ON observations (dockyard_id, observed_at);
CREATE TABLE evidence_records (
    id INTEGER NOT NULL PRIMARY KEY,
    dockyard_id INTEGER NOT NULL,
    discovery_run_id INTEGER NOT NULL,
    kind VARCHAR(16) NOT NULL,
    relative_path VARCHAR(255) NOT NULL,
    media_type VARCHAR(64) NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    truncated BOOLEAN NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY(dockyard_id) REFERENCES dockyards (id) ON DELETE CASCADE,
    FOREIGN KEY(discovery_run_id) REFERENCES discovery_runs (id) ON DELETE CASCADE
);
"""

#: One Dockyard as v0.2.1 would have left it: a probed HTTP origin whose
#: response predates RedDock recording which headers it examined, and a service
#: nmap identified.
PHASE_1_DATA = """
INSERT INTO dockyards (id, name, description, status)
VALUES (1, 'Existing engagement', 'From 0.2.1', 'draft');
INSERT INTO scope_entries (dockyard_id, rule, kind, value)
VALUES (1, 'include', 'ipv4', '127.0.0.1');
INSERT INTO discovery_runs (
    id, dockyard_id, adapter, adapter_version, profile, requested_target,
    normalized_target, status, decision, decision_reason,
    asset_count, service_count, observation_count, evidence_path)
VALUES (1, 1, 'http', '1.0.0', 'http_probe', 'https://127.0.0.1:8443',
    'https://127.0.0.1:8443', 'completed', 'allowed', 'In scope', 1, 1, 2, '1/1');
INSERT INTO assets (
    id, dockyard_id, asset_type, identity, display_name, ip_address, first_seen, last_seen)
VALUES (1, 1, 'web', 'https://127.0.0.1:8443', 'https://127.0.0.1:8443',
    '127.0.0.1', '2026-08-01 12:00:00', '2026-08-01 12:00:00');
INSERT INTO services (id, asset_id, transport, port, state, service_name, first_seen, last_seen)
VALUES (1, 1, 'tcp', 8443, 'open', 'https', '2026-08-01 12:00:00', '2026-08-01 12:00:00');
INSERT INTO assets (
    id, dockyard_id, asset_type, identity, display_name, ip_address, first_seen, last_seen)
VALUES (2, 1, 'host', '127.0.0.1', '127.0.0.1', '127.0.0.1',
    '2026-08-01 12:00:00', '2026-08-01 12:00:00');
INSERT INTO services (
    id, asset_id, transport, port, state, service_name, product, version, first_seen, last_seen)
VALUES (2, 2, 'tcp', 23, 'open', 'telnet', 'Linux telnetd', NULL,
    '2026-08-01 12:00:00', '2026-08-01 12:00:00');
INSERT INTO observations (
    dockyard_id, discovery_run_id, asset_id, service_id, adapter, observation_type,
    summary, detail, confidence, raw_reference, observed_at)
VALUES (1, 1, 1, 1, 'http', 'http_response', 'https://127.0.0.1:8443 returned HTTP 200',
    '{"status": 200, "address": "127.0.0.1"}', 'observed', '1/1', '2026-08-01 12:00:00');
INSERT INTO observations (
    dockyard_id, discovery_run_id, asset_id, service_id, adapter, observation_type,
    summary, detail, confidence, raw_reference, observed_at)
VALUES (1, 1, 2, 2, 'nmap', 'service_identified', 'TCP/23 identified as Linux telnetd',
    '{"name": "telnet", "product": "Linux telnetd"}', 'reported', '1/1', '2026-08-01 12:00:00');
INSERT INTO evidence_records (
    dockyard_id, discovery_run_id, kind, relative_path, media_type, size_bytes, sha256, truncated)
VALUES (1, 1, 'normalized', 'normalized/result.json', 'application/json', 256,
    '1111111111111111111111111111111111111111111111111111111111111111', 0);
"""


@pytest.fixture()
def phase_1_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    database = tmp_path / "reddock.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(PHASE_1_SCHEMA)
        connection.executescript(PHASE_1_DATA)
    monkeypatch.setenv("REDDOCK_DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("REDDOCK_EVIDENCE_DIR", str(tmp_path / "evidence"))
    import app.config

    app.config.get_settings.cache_clear()
    import app.database

    app.database.configure_engine()
    yield database
    app.config.get_settings.cache_clear()


def test_every_phase_2_table_is_created(phase_1_database: Path):
    import app.database

    app.database.initialize_database()
    with sqlite3.connect(phase_1_database) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in rows}
    assert {"detection_runs", "findings", "finding_evidence"} <= tables


def test_every_phase_3_table_is_created(phase_1_database: Path):
    """Phase 3 remains additive when upgrading a prior persisted Dockyard."""
    import app.database

    app.database.initialize_database()
    with sqlite3.connect(phase_1_database) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in rows}
    assert "validation_runs" in tables


def test_every_phase_4_table_is_created(phase_1_database: Path):
    """Phase 4 adds snapshots without changing prior persisted records."""
    import app.database

    app.database.initialize_database()
    with sqlite3.connect(phase_1_database) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in rows}
    assert {
        "correlation_runs",
        "asset_relationships",
        "finding_correlations",
        "framework_mappings",
    } <= tables


def test_every_phase_5_table_is_created(phase_1_database: Path):
    """Phase 5 adds reviewable advice without changing prior tables."""
    import app.database

    app.database.initialize_database()
    with sqlite3.connect(phase_1_database) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in rows}
    assert "intelligence_runs" in tables


def test_every_phase_6_table_is_created(phase_1_database: Path):
    """Phase 6 adds immutable report snapshots without changing prior tables."""
    import app.database

    app.database.initialize_database()
    with sqlite3.connect(phase_1_database) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in rows}
    assert "report_runs" in tables


def test_phase_2_changes_no_phase_1_column(phase_1_database: Path):
    """The upgrade is additive, so every Phase 1 table keeps the shape it had."""
    import app.database

    before = _columns(phase_1_database)
    app.database.initialize_database()
    after = _columns(phase_1_database)

    for table, columns in before.items():
        assert after[table] == columns, table


def test_phase_1_data_survives_and_phase_2_runs_on_top_of_it(phase_1_database: Path):
    from fastapi.testclient import TestClient

    import app.database
    import app.main

    app.database.initialize_database()
    with TestClient(app.main.app, base_url="http://localhost") as client:
        assert [row["name"] for row in client.get("/api/dockyards").json()] == [
            "Existing engagement"
        ]
        assert len(client.get("/api/dockyards/1/assets").json()) == 2
        assert len(client.get("/api/dockyards/1/observations").json()) == 2

        run = client.post("/api/dockyards/1/detections", json={})
        assert run.status_code == 201, run.text
        assert run.json()["status"] == "completed"

        findings = client.get("/api/dockyards/1/findings").json()
        rules = {finding["rule_id"] for finding in findings}

        # A rule that needs only what v0.2.1 recorded still works...
        assert "cleartext-remote-administration" in rules
        # ...and one that needs to know which headers were examined stays silent
        # rather than claiming a header was absent from a response nobody
        # inspected for it.
        assert not rules & {
            "hsts-not-set",
            "content-security-policy-not-set",
            "content-type-options-not-nosniff",
            "frame-protection-not-set",
        }

        detail = client.get(f"/api/dockyards/1/findings/{findings[0]['id']}").json()
        assert detail["evidence"][0]["sha256"] == "1" * 64


def _columns(database: Path) -> dict[str, list[tuple]]:
    with sqlite3.connect(database) as connection:
        names = [
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        ]
        return {
            name: list(connection.execute(f"PRAGMA table_info({name})"))  # noqa: S608 - fixed names
            for name in names
        }
