import os
from uuid import uuid4

import pytest
from sqlalchemy import inspect, select


def test_postgresql_migrations_and_crud(tmp_path, monkeypatch: pytest.MonkeyPatch):
    url = os.getenv("REDDOCK_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("REDDOCK_TEST_POSTGRES_URL is not configured")

    import app.config
    import app.database
    from app.models import Dockyard

    monkeypatch.setenv("REDDOCK_DATABASE_URL", url)
    for name in (
        "REDDOCK_DATABASE_HOST",
        "REDDOCK_DATABASE_PORT",
        "REDDOCK_DATABASE_NAME",
        "REDDOCK_DATABASE_USER",
        "REDDOCK_DATABASE_PASSWORD_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    app.config.get_settings.cache_clear()
    app.database.configure_engine()

    try:
        app.database.initialize_database()
        assert app.database.engine.dialect.name == "postgresql"
        assert inspect(app.database.engine).has_table("dockyards")
        assert inspect(app.database.engine).has_table("security_audit_events")
        with app.database.engine.begin() as connection:
            assert (
                connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
                == "0003_security_audit"
            )
            assert connection.exec_driver_sql(
                "INSERT INTO organizations (slug, name) "
                "VALUES ('sequence-check', 'Sequence check') RETURNING id"
            ).scalar_one() == 2

        marker = f"PostgreSQL integration {uuid4()}"
        with app.database.SessionLocal() as session:
            dockyard = Dockyard(name=marker, description="CI migration and CRUD proof")
            session.add(dockyard)
            session.commit()
            dockyard_id = dockyard.id

        with app.database.SessionLocal() as session:
            stored = session.scalar(select(Dockyard).where(Dockyard.id == dockyard_id))
            assert stored is not None
            assert stored.name == marker
            assert stored.organization_id == 1
            session.delete(stored)
            session.commit()
    finally:
        monkeypatch.setenv("REDDOCK_DATABASE_URL", f"sqlite:///{tmp_path / 'after-postgres.db'}")
        app.config.get_settings.cache_clear()
        app.database.configure_engine()
