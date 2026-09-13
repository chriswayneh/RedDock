from unittest.mock import Mock

import pytest
from pydantic import SecretBytes, SecretStr, ValidationError
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection

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
        rate_limit_database_user="reddock_limiter",
        rate_limit_database_password=SecretStr("limiter-database-secret"),
        server_workers=1,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"rate_limit_database_user": "reddock"},
        {"rate_limit_database_password": SecretStr("database-secret")},
    ],
)
def test_server_runtime_model_rejects_limiter_credential_reuse(overrides):
    values = _server_config().model_dump()
    values.update(overrides)

    with pytest.raises(ValidationError):
        DormantServerRuntimeConfig(**values)


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


def test_server_primary_factory_uses_only_exact_config_and_fixed_postgres_policy(monkeypatch):
    import app.database

    captured: dict[str, object] = {}
    candidate = create_engine("sqlite://")

    def factory(url, **options):
        captured["url"] = url
        captured.update(options)
        return candidate

    monkeypatch.setattr(app.database, "create_engine", factory)
    monkeypatch.setattr(app.database, "_primary_connection_is_exact", lambda *_args, **_kw: True)

    runtime = app.database.create_server_primary_database_runtime(_server_config())
    try:
        assert repr(runtime) == "PrimaryDatabaseRuntime(ready=False, closed=False)"
        assert captured["pool_size"] == app.database.POSTGRES_APPLICATION_POOL_SIZE == 5
        assert captured["max_overflow"] == app.database.POSTGRES_APPLICATION_MAX_OVERFLOW == 10
        assert captured["pool_timeout"] == 5
        assert captured["pool_pre_ping"] is True
        assert captured["isolation_level"] == "READ COMMITTED"
        assert captured["execution_options"] == {
            "schema_translate_map": {None: "public"}
        }
        assert captured["connect_args"] == {
            "connect_timeout": 5,
            "application_name": "reddock-server-main",
            "options": (
                "-c statement_timeout=120000 -c lock_timeout=5000 "
                "-c idle_in_transaction_session_timeout=660000 "
                "-c transaction_timeout=900000 -c search_path=pg_catalog,public"
            ),
        }
        rendered_url = captured["url"]
        assert rendered_url.username == "reddock"
        assert rendered_url.password == "database-secret"
        assert rendered_url.host == "postgres"
        assert rendered_url.port == 5432
        assert rendered_url.database == "reddock"
        assert "database-secret" not in str(rendered_url)
        with pytest.raises(app.database.PrimaryDatabaseUnavailable):
            runtime.session()
    finally:
        runtime.close()


def test_server_primary_factory_disposes_failed_attestation_without_secret_leak(monkeypatch):
    import app.database

    candidate = create_engine("sqlite://")
    dispose = Mock(wraps=candidate.dispose)
    monkeypatch.setattr(candidate, "dispose", dispose)
    monkeypatch.setattr(app.database, "create_engine", lambda *_args, **_options: candidate)

    with pytest.raises(
        app.database.PrimaryDatabaseUnavailable,
        match="primary database runtime is unavailable",
    ) as error:
        app.database.create_server_primary_database_runtime(_server_config())

    assert dispose.call_count == 1
    assert "database-secret" not in str(error.value)
    assert error.value.__cause__ is None


def test_server_primary_runtime_becomes_ready_once_and_closes_idempotently(monkeypatch):
    import app.database
    import app.migration_runner

    candidate = create_engine("sqlite://")
    dispose = Mock(wraps=candidate.dispose)
    original_execute = Connection.execute

    def execute(connection, statement, *args, **kwargs):
        rendered = str(statement)
        if "set_config('lock_timeout'" in rendered:
            return Mock()
        if "pg_advisory_lock" in rendered:
            return Mock(scalar_one_or_none=lambda: None)
        if "pg_advisory_unlock" in rendered:
            return Mock(scalar_one=lambda: True)
        return original_execute(connection, statement, *args, **kwargs)

    monkeypatch.setattr(candidate, "dispose", dispose)
    monkeypatch.setattr(Connection, "execute", execute)
    monkeypatch.setattr(app.database, "_primary_connection_is_exact", lambda *_args, **_kw: True)
    upgrade = Mock()
    monkeypatch.setattr(app.migration_runner, "upgrade_database_connection", upgrade)
    runtime = app.database.PrimaryDatabaseRuntime(_server_config(), candidate)

    with runtime.startup_session() as startup_session:
        assert startup_session.bind.engine is candidate

    assert upgrade.call_count == 1
    assert runtime.engine is candidate
    session = runtime.session()
    session.close()
    with pytest.raises(app.database.PrimaryDatabaseUnavailable):
        with runtime.startup_session():
            pass

    runtime.close()
    runtime.close()
    assert dispose.call_count == 1
    assert repr(runtime) == "PrimaryDatabaseRuntime(ready=False, closed=True)"
    with pytest.raises(app.database.PrimaryDatabaseUnavailable):
        runtime.session()


def test_server_primary_runtime_discards_an_uncertain_advisory_lock_connection(monkeypatch):
    import app.database

    candidate = create_engine("sqlite://")
    original_execute = Connection.execute
    original_invalidate = Connection.invalidate
    invalidated: list[Connection] = []

    def execute(connection, statement, *args, **kwargs):
        rendered = str(statement)
        if "set_config('lock_timeout'" in rendered:
            return Mock()
        if "pg_advisory_lock" in rendered:
            raise app.database.SQLAlchemyError("uncertain transport failure")
        return original_execute(connection, statement, *args, **kwargs)

    def invalidate(connection, *args, **kwargs):
        invalidated.append(connection)
        return original_invalidate(connection, *args, **kwargs)

    monkeypatch.setattr(Connection, "execute", execute)
    monkeypatch.setattr(Connection, "invalidate", invalidate)
    monkeypatch.setattr(app.database, "_primary_connection_is_exact", lambda *_args, **_kw: True)
    runtime = app.database.PrimaryDatabaseRuntime(_server_config(), candidate)

    with pytest.raises(
        app.database.PrimaryDatabaseUnavailable,
        match="primary database runtime is unavailable",
    ) as error:
        with runtime.startup_session():
            pass

    assert len(invalidated) == 1
    assert error.value.__cause__ is None
    runtime.close()


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
        assert captured["execution_options"] == {
            "schema_translate_map": {None: "public"}
        }
        assert captured["connect_args"] == {
            "connect_timeout": 5,
            "application_name": "reddock-limiter",
            "options": (
                "-c statement_timeout=2000 -c lock_timeout=1000 "
                "-c search_path=pg_catalog,public"
            ),
        }
        rendered_url = captured["url"]
        assert rendered_url.username == "reddock_limiter"
        assert rendered_url.password == "limiter-database-secret"
        assert "database-secret" not in str(rendered_url)
        assert "limiter-database-secret" not in str(rendered_url)
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
