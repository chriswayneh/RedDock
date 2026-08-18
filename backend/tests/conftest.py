import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("REDDOCK_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    # Modules read settings at import time; isolate after changing the database URL.
    import app.config

    app.config.get_settings.cache_clear()
    import app.database
    import app.main

    app.database.engine.dispose()
    app.database.settings = app.config.get_settings()
    app.database.engine = app.database.create_engine(
        app.database.settings.database_url, connect_args={"check_same_thread": False}
    )
    app.database.SessionLocal.configure(bind=app.database.engine)
    with TestClient(app.main.app) as test_client:
        yield test_client
    os.environ.pop("REDDOCK_DATABASE_URL", None)
