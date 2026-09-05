import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import inspect


def test_fresh_database_is_stamped_at_the_current_head(environment: Path):
    import app.database

    app.database.initialize_database()

    with app.database.engine.connect() as connection:
        assert inspect(connection).has_table("dockyards")
        assert (
            connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0001_v080"
        )


def test_migration_runner_is_idempotent(environment: Path):
    import app.database

    app.database.initialize_database()
    app.database.initialize_database()

    with app.database.engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM alembic_version").scalar_one() == 1


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
