import sqlite3
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError


def test_fresh_database_is_stamped_at_the_current_head(environment: Path):
    import app.database

    app.database.initialize_database()

    with app.database.engine.connect() as connection:
        assert inspect(connection).has_table("dockyards")
        assert inspect(connection).has_table("security_audit_events")
        assert inspect(connection).has_table("oidc_login_attempts")
        assert inspect(connection).has_table("rate_limit_buckets")
        assert (
            connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0006_session_lifecycle"
        )
        assert (
            connection.exec_driver_sql("SELECT name FROM organizations WHERE id = 1").scalar_one()
            == "Local RedDock"
        )
        assert (
            connection.exec_driver_sql("SELECT display_name FROM users WHERE id = 1").scalar_one()
            == "Local operator"
        )
        assert (
            connection.exec_driver_sql("SELECT role FROM memberships WHERE id = 1").scalar_one()
            == "owner"
        )
        assert (
            connection.exec_driver_sql(
                "INSERT INTO organizations (slug, name) VALUES ('next', 'Next') RETURNING id"
            ).scalar_one()
            == 2
        )


def test_migration_runner_is_idempotent(environment: Path):
    import app.database

    app.database.initialize_database()
    app.database.initialize_database()

    with app.database.engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM alembic_version").scalar_one() == 1


def test_rate_limit_migration_upgrades_the_oidc_schema_in_place(environment: Path):
    import app.database
    from app.migration_runner import _config

    app.database.initialize_database()
    with app.database.engine.begin() as connection:
        command.downgrade(_config(connection), "0004_oidc_attempts")
        assert not inspect(connection).has_table("rate_limit_buckets")
        assert (
            connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0004_oidc_attempts"
        )

    app.database.initialize_database()
    with app.database.engine.connect() as connection:
        assert inspect(connection).has_table("rate_limit_buckets")
        assert (
            connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0006_session_lifecycle"
        )


def test_session_lifecycle_migration_backfills_and_enforces_family_state(
    environment: Path,
):
    import app.database
    from app.migration_runner import _config

    app.database.initialize_database()
    with app.database.engine.begin() as connection:
        command.downgrade(_config(connection), "0005_rate_limits")
        legacy_columns = {column["name"]: column for column in inspect(connection).get_columns(
            "browser_sessions"
        )}
        assert legacy_columns["created_at"]["nullable"] is True
        assert "family_hash" not in legacy_columns
        connection.exec_driver_sql(
            """
            INSERT INTO browser_sessions (
                id, token_hash, csrf_token_hash, membership_id, created_at,
                last_seen_at, expires_at, revoked_at
            ) VALUES (
                1, ?, ?, 1, NULL, ?, ?, NULL
            )
            """,
            (
                "a" * 64,
                "b" * 64,
                "2026-09-14 12:00:00",
                "2026-09-15 12:00:00",
            ),
        )
        connection.exec_driver_sql(
            """
            INSERT INTO browser_sessions (
                id, token_hash, csrf_token_hash, membership_id, created_at,
                last_seen_at, expires_at, revoked_at
            ) VALUES (
                2, ?, ?, 1, ?, ?, ?, NULL
            )
            """,
            (
                "e" * 64,
                "f" * 64,
                "2026-09-14 12:00:01",
                "2026-09-14 12:00:00",
                "2026-09-15 12:00:00",
            ),
        )

    app.database.initialize_database()
    with app.database.engine.connect() as connection:
        assert (
            connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0006_session_lifecycle"
        )
        row = connection.exec_driver_sql(
            """
            SELECT token_hash, family_hash, generation, created_at,
                   last_seen_at, token_issued_at, replaced_at
            FROM browser_sessions WHERE id = 1
            """
        ).mappings().one()
        assert row["family_hash"] == row["token_hash"] == "a" * 64
        assert row["generation"] == 0
        assert row["created_at"] == row["last_seen_at"] == "2026-09-14 12:00:00"
        assert row["token_issued_at"] == row["last_seen_at"]
        assert row["replaced_at"] is None
        skewed = connection.exec_driver_sql(
            """
            SELECT created_at, last_seen_at, token_issued_at
            FROM browser_sessions WHERE id = 2
            """
        ).mappings().one()
        assert skewed["created_at"] == "2026-09-14 12:00:00"
        assert skewed["token_issued_at"] == skewed["last_seen_at"]

        columns = {column["name"]: column for column in inspect(connection).get_columns(
            "browser_sessions"
        )}
        for name in ("created_at", "family_hash", "generation", "token_issued_at"):
            assert columns[name]["nullable"] is False
        assert columns["replaced_at"]["nullable"] is True
        checks = {
            constraint["name"]
            for constraint in inspect(connection).get_check_constraints("browser_sessions")
        }
        assert {
            "ck_browser_session_token_hash",
            "ck_browser_session_csrf_hash",
            "ck_browser_session_family_hash",
            "ck_browser_session_generation",
            "ck_browser_session_created_before_token",
            "ck_browser_session_token_before_seen",
            "ck_browser_session_seen_before_expiry",
        } <= checks
        unique_constraints = {
            constraint["name"]: constraint["column_names"]
            for constraint in inspect(connection).get_unique_constraints("browser_sessions")
        }
        assert unique_constraints["uq_browser_session_family_generation"] == [
            "family_hash",
            "generation",
        ]
        indexes = {
            index["name"]: (index["column_names"], index["unique"])
            for index in inspect(connection).get_indexes("browser_sessions")
        }
        assert indexes["ix_browser_sessions_last_seen"] == (["last_seen_at", "id"], 0)
        assert indexes["uq_browser_sessions_active_family"] == (["family_hash"], 1)
        index_sql = connection.exec_driver_sql(
            "SELECT sql FROM sqlite_master WHERE type = 'index' "
            "AND name = 'uq_browser_sessions_active_family'"
        ).scalar_one()
        assert "WHERE replaced_at IS NULL AND revoked_at IS NULL" in index_sql

    with pytest.raises(IntegrityError):
        with app.database.engine.begin() as connection:
            connection.exec_driver_sql(
                """
                INSERT INTO browser_sessions (
                    token_hash, csrf_token_hash, membership_id, created_at,
                    last_seen_at, expires_at, revoked_at, family_hash,
                    generation, token_issued_at, replaced_at
                ) VALUES (?, ?, 1, ?, ?, ?, NULL, ?, 1, ?, NULL)
                """,
                (
                    "c" * 64,
                    "d" * 64,
                    "2026-09-14 12:01:00",
                    "2026-09-14 12:01:00",
                    "2026-09-15 12:00:00",
                    "a" * 64,
                    "2026-09-14 12:01:00",
                ),
            )

    with app.database.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE browser_sessions SET replaced_at = ? WHERE id = 1",
            ("2026-09-14 12:01:00",),
        )
        connection.exec_driver_sql(
            """
            INSERT INTO browser_sessions (
                token_hash, csrf_token_hash, membership_id, created_at,
                last_seen_at, expires_at, revoked_at, family_hash,
                generation, token_issued_at, replaced_at
            ) VALUES (?, ?, 1, ?, ?, ?, NULL, ?, 1, ?, NULL)
            """,
            (
                "c" * 64,
                "d" * 64,
                "2026-09-14 12:01:00",
                "2026-09-14 12:01:00",
                "2026-09-15 12:00:00",
                "a" * 64,
                "2026-09-14 12:01:00",
            ),
        )

    with app.database.engine.begin() as connection:
        command.downgrade(_config(connection), "0005_rate_limits")
        downgraded_columns = {
            column["name"]
            for column in inspect(connection).get_columns("browser_sessions")
        }
        assert "replaced_at" not in downgraded_columns
        assert (
            connection.exec_driver_sql(
                "SELECT revoked_at FROM browser_sessions WHERE id = 1"
            ).scalar_one()
            == "2026-09-14 12:01:00"
        )


def test_rate_limit_migration_refuses_a_malformed_preexisting_table(environment: Path):
    import app.database
    from app.migration_runner import _config

    app.database.initialize_database()
    with app.database.engine.begin() as connection:
        command.downgrade(_config(connection), "0004_oidc_attempts")
        connection.exec_driver_sql(
            "CREATE TABLE rate_limit_buckets (id INTEGER PRIMARY KEY, action VARCHAR(48))"
        )

    with pytest.raises(RuntimeError, match="Unexpected preexisting rate_limit_buckets table"):
        app.database.initialize_database()

    with app.database.engine.connect() as connection:
        assert (
            connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0004_oidc_attempts"
        )


def test_rate_limit_migration_refuses_an_exact_preexisting_table(environment: Path):
    import app.database
    from app.migration_runner import _config

    app.database.initialize_database()
    with app.database.engine.begin() as connection:
        command.downgrade(_config(connection), "0004_oidc_attempts")
        connection.exec_driver_sql(
            """
            CREATE TABLE rate_limit_buckets (
                id INTEGER PRIMARY KEY,
                action VARCHAR(48) NOT NULL,
                key_hash VARCHAR(64) NOT NULL,
                attempt_count INTEGER NOT NULL,
                expires_at DATETIME NOT NULL,
                CONSTRAINT ck_rate_limit_action
                    CHECK (action IN ('oidc.login', 'oidc.callback', 'request.mutation')),
                CONSTRAINT ck_rate_limit_key_hash CHECK (length(key_hash) = 64),
                CONSTRAINT ck_rate_limit_attempt_count
                    CHECK (attempt_count BETWEEN 1 AND 1000000),
                CONSTRAINT uq_rate_limit_bucket UNIQUE (action, key_hash)
            )
            """
        )
        connection.exec_driver_sql(
            "CREATE INDEX ix_rate_limit_expiry ON rate_limit_buckets (expires_at, id)"
        )

    with pytest.raises(RuntimeError, match="Unexpected preexisting rate_limit_buckets table"):
        app.database.initialize_database()

    with app.database.engine.connect() as connection:
        assert (
            connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0004_oidc_attempts"
        )


def test_rate_limit_migration_refuses_named_but_narrow_constraints(environment: Path):
    import app.database
    from app.migration_runner import _config

    app.database.initialize_database()
    with app.database.engine.begin() as connection:
        command.downgrade(_config(connection), "0004_oidc_attempts")
        connection.exec_driver_sql(
            """
            CREATE TABLE rate_limit_buckets (
                id INTEGER PRIMARY KEY,
                action VARCHAR(48) NOT NULL,
                key_hash VARCHAR(64) NOT NULL,
                attempt_count INTEGER NOT NULL,
                expires_at DATETIME NOT NULL,
                CONSTRAINT ck_rate_limit_action CHECK (action <> 'unsupported'),
                CONSTRAINT ck_rate_limit_key_hash CHECK (length(key_hash) <> 63),
                CONSTRAINT ck_rate_limit_attempt_count
                    CHECK (attempt_count NOT IN (0, 1000001)),
                CONSTRAINT uq_rate_limit_bucket UNIQUE (action, key_hash)
            )
            """
        )
        connection.exec_driver_sql(
            "CREATE INDEX ix_rate_limit_expiry ON rate_limit_buckets (expires_at, id)"
        )

    with pytest.raises(RuntimeError, match="Unexpected preexisting rate_limit_buckets table"):
        app.database.initialize_database()

    with app.database.engine.connect() as connection:
        assert (
            connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0004_oidc_attempts"
        )


def test_legacy_database_with_an_unknown_shape_fails_before_stamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    database = tmp_path / "corrupt.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE dockyards (id INTEGER PRIMARY KEY)")

    monkeypatch.setenv("REDDOCK_DATABASE_URL", f"sqlite:///{database}")
    import app.config
    import app.database

    app.config.get_settings.cache_clear()
    app.database.configure_engine()

    with pytest.raises(RuntimeError, match="does not match the released RedDock v0.8.0 schema"):
        app.database.initialize_database()

    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "alembic_version" not in tables


def test_frozen_baseline_is_a_subset_of_the_current_model():
    from app import models  # noqa: F401
    from app.database import Base
    from app.migration_runner import BASELINE_SCHEMA

    for table, expected_columns in BASELINE_SCHEMA.items():
        assert table in Base.metadata.tables
        assert set(expected_columns) <= set(Base.metadata.tables[table].columns.keys())


def test_new_dockyards_are_owned_by_the_local_organization(environment: Path):
    import app.database
    from app.models import Dockyard

    app.database.initialize_database()
    with app.database.SessionLocal() as session:
        dockyard = Dockyard(name="Owned local workspace")
        session.add(dockyard)
        session.commit()
        session.refresh(dockyard)
        assert dockyard.organization_id == 1
