from unittest.mock import Mock

import pytest
from pydantic import SecretBytes, SecretStr
from sqlalchemy import create_engine

from app.config import DormantServerRuntimeConfig
from app.rate_limits import RateLimitUnavailable


def _server_config() -> DormantServerRuntimeConfig:
    return DormantServerRuntimeConfig(
        public_origin="https://reddock.example",
        oidc_issuer="https://identity.example/realms/reddock",
        oidc_client_id="reddock",
        oidc_client_secret=SecretStr("client-secret"),
        oidc_endpoint_origins=("https://identity.example",),
        organization_slug="server-team",
        database_host="postgres",
        database_port=5432,
        database_name="reddock",
        database_user="reddock",
        database_password=SecretStr("database-secret"),
        rate_limit_key=SecretBytes(bytes.fromhex("ab" * 32)),
    )


def test_application_postgres_pool_has_an_explicit_connection_budget(monkeypatch):
    import app.database

    captured: dict[str, object] = {}
    candidate = create_engine("sqlite://")

    def factory(url, **options):
        captured["url"] = url
        captured.update(options)
        return candidate

    monkeypatch.setattr(app.database, "create_engine", factory)
    assert app.database._application_engine("postgresql+psycopg://db/reddock") is candidate
    assert captured["pool_size"] == app.database.POSTGRES_APPLICATION_POOL_SIZE == 5
    assert captured["max_overflow"] == app.database.POSTGRES_APPLICATION_MAX_OVERFLOW == 10
    assert captured["pool_timeout"] == 5
    assert captured["pool_pre_ping"] is True
    assert captured["connect_args"] == {
        "connect_timeout": 5,
        "application_name": "reddock-app",
    }


def test_limiter_factory_builds_and_primes_a_distinct_bounded_pool(monkeypatch):
    import app.database

    captured: dict[str, object] = {}
    candidate = create_engine("sqlite://")
    with candidate.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE rate_limit_buckets (id INTEGER PRIMARY KEY)")

    def factory(url, **options):
        captured["url"] = url
        captured.update(options)
        return candidate

    monkeypatch.setattr(app.database, "create_engine", factory)
    runtime = app.database.create_rate_limiter_runtime(_server_config())
    try:
        assert repr(runtime) == "RateLimiterRuntime(closed=False)"
        assert captured["pool_size"] == app.database.POSTGRES_LIMITER_POOL_SIZE == 2
        assert captured["max_overflow"] == 0
        assert captured["pool_timeout"] == 2
        assert captured["pool_pre_ping"] is True
        assert captured["isolation_level"] == "READ COMMITTED"
        assert captured["connect_args"] == {
            "connect_timeout": 5,
            "application_name": "reddock-limiter",
            "options": "-c statement_timeout=2000 -c lock_timeout=1000",
        }
        rendered_url = captured["url"]
        assert "database-secret" not in str(rendered_url)
    finally:
        runtime.close()
    assert repr(runtime) == "RateLimiterRuntime(closed=True)"


def test_limiter_factory_disposes_a_failed_candidate_without_leaking_details(monkeypatch):
    import app.database

    candidate = create_engine("sqlite://")
    dispose = Mock(wraps=candidate.dispose)
    monkeypatch.setattr(candidate, "dispose", dispose)
    monkeypatch.setattr(app.database, "create_engine", lambda *_args, **_options: candidate)

    with pytest.raises(RateLimitUnavailable, match="durable rate limiter is unavailable") as error:
        app.database.create_rate_limiter_runtime(_server_config())

    assert dispose.call_count == 1
    assert "database-secret" not in str(error.value)
    assert error.value.__cause__ is None


def test_failed_application_engine_reconfiguration_preserves_the_live_engine(
    environment, monkeypatch
):
    import app.database

    live_engine = app.database.engine

    def fail_to_build(_url):
        raise RuntimeError("candidate failed")

    monkeypatch.setattr(app.database, "_application_engine", fail_to_build)
    with pytest.raises(RuntimeError, match="candidate failed"):
        app.database.configure_engine()

    assert app.database.engine is live_engine
    assert app.database.SessionLocal.kw["bind"] is live_engine


def test_successful_application_engine_reconfiguration_rebinds_then_disposes(
    environment, monkeypatch
):
    import app.database

    previous = app.database.engine
    dispose = Mock(wraps=previous.dispose)
    candidate = create_engine("sqlite://")
    monkeypatch.setattr(previous, "dispose", dispose)
    monkeypatch.setattr(app.database, "_application_engine", lambda _url: candidate)

    app.database.configure_engine()

    assert app.database.engine is candidate
    assert app.database.SessionLocal.kw["bind"] is candidate
    assert dispose.call_count == 1
