from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretBytes, SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import DormantServerRuntimeConfig
from app.database import DATABASE_REQUEST_BINDING_STATE
from app.main import build_lifespan, create_app


def _config() -> DormantServerRuntimeConfig:
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
        rate_limit_key=SecretBytes(b"r" * 32),
        rate_limit_database_user="reddock_limiter",
        rate_limit_database_password=SecretStr("limiter-database-secret"),
        server_workers=1,
    )


class FakeProvider:
    def __init__(self, config: DormantServerRuntimeConfig) -> None:
        self.config = config
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class FakeLimiter:
    def __init__(self, config: DormantServerRuntimeConfig) -> None:
        self.config = config
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class FakeAuthentication:
    def __init__(self, config, provider, limiter, lifecycle_engine) -> None:
        self.config = config
        self.provider = provider
        self.limiter = limiter
        self.lifecycle_engine = lifecycle_engine
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class FakePrimaryDatabase:
    def __init__(self, config: DormantServerRuntimeConfig) -> None:
        self.config = config
        self.engine = create_engine("sqlite://")
        self.startup_session_value = object()
        self.startup_calls = 0
        self.close_calls = 0

    @contextmanager
    def startup_session(self):
        self.startup_calls += 1
        yield self.startup_session_value

    def session(self) -> Session:
        return Session(self.engine)

    def close(self) -> None:
        self.close_calls += 1
        self.engine.dispose()


class FakePrimaryFactory:
    def __init__(self) -> None:
        self.created: list[FakePrimaryDatabase] = []

    def __call__(self, config: DormantServerRuntimeConfig) -> FakePrimaryDatabase:
        runtime = FakePrimaryDatabase(config)
        self.created.append(runtime)
        return runtime


@pytest.fixture(autouse=True)
def recovered_sessions(monkeypatch):
    import app.main

    recovered: list[object] = []
    monkeypatch.setattr(app.main, "_recover_interrupted_work", recovered.append)
    return recovered


def test_configured_lifespan_owns_exactly_one_provider_per_application(
    environment, recovered_sessions
):
    created: list[FakeProvider] = []
    limiters: list[FakeLimiter] = []
    authenticators: list[FakeAuthentication] = []
    primary_factory = FakePrimaryFactory()

    def provider_factory(config: DormantServerRuntimeConfig) -> FakeProvider:
        provider = FakeProvider(config)
        created.append(provider)
        return provider

    def limiter_factory(config: DormantServerRuntimeConfig) -> FakeLimiter:
        limiter = FakeLimiter(config)
        limiters.append(limiter)
        return limiter

    def authentication_factory(config, provider, limiter, lifecycle_engine):
        authenticator = FakeAuthentication(config, provider, limiter, lifecycle_engine)
        authenticators.append(authenticator)
        return authenticator

    applications = [
        FastAPI(
            lifespan=build_lifespan(
                _config(),
                provider_factory=provider_factory,
                limiter_factory=limiter_factory,
                primary_database_factory=primary_factory,
                authentication_factory=authentication_factory,
            )
        )
        for _ in range(2)
    ]

    for application in applications:
        with TestClient(application) as client:
            first = application.state.authentication_runtime
            assert client.get("/").status_code == 404
            assert application.state.authentication_runtime is first
            assert first.provider is created[-1]
            assert first.limiter is limiters[-1]
            assert first.lifecycle_engine is primary_factory.created[-1].engine
            assert first.config is not None
            assert application.state.primary_database_runtime is primary_factory.created[-1]
            assert not hasattr(application.state, "oidc_provider")
            assert not hasattr(application.state, "rate_limiter")
        assert not hasattr(application.state, "authentication_runtime")
        assert not hasattr(application.state, "primary_database_runtime")
        assert not hasattr(application.state, DATABASE_REQUEST_BINDING_STATE)

    assert len(primary_factory.created) == 2
    assert len(created) == 2
    assert len(limiters) == 2
    assert len(authenticators) == 2
    assert created[0] is not created[1]
    assert [runtime.close_calls for runtime in authenticators] == [1, 1]
    assert [provider.close_calls for provider in created] == [1, 1]
    assert [limiter.close_calls for limiter in limiters] == [1, 1]
    assert [runtime.startup_calls for runtime in primary_factory.created] == [1, 1]
    assert [runtime.close_calls for runtime in primary_factory.created] == [1, 1]
    assert recovered_sessions == [
        runtime.startup_session_value for runtime in primary_factory.created
    ]


def test_configured_lifespan_starts_and_closes_capabilities_in_exact_order(
    environment, monkeypatch
):
    import app.main

    events: list[str] = []

    class OrderedPrimary(FakePrimaryDatabase):
        @contextmanager
        def startup_session(self):
            events.append("primary.startup")
            yield self.startup_session_value

        def close(self) -> None:
            events.append("primary.close")
            super().close()

    class OrderedLimiter(FakeLimiter):
        def close(self) -> None:
            events.append("limiter.close")
            super().close()

    class OrderedProvider(FakeProvider):
        def close(self) -> None:
            events.append("provider.close")
            super().close()

    class OrderedAuthentication(FakeAuthentication):
        def close(self) -> None:
            events.append("authentication.close")
            super().close()

    primary_runtime = None

    def primary_factory(config):
        nonlocal primary_runtime
        events.append("primary.create")
        primary_runtime = OrderedPrimary(config)
        return primary_runtime

    def limiter_factory(config):
        events.append("limiter.create")
        return OrderedLimiter(config)

    def provider_factory(config):
        events.append("provider.create")
        return OrderedProvider(config)

    def authentication_factory(config, provider, limiter, engine):
        events.append("authentication.create")
        return OrderedAuthentication(config, provider, limiter, engine)

    monkeypatch.setattr(
        app.main,
        "_recover_interrupted_work",
        lambda session: events.append("recovery"),
    )
    config = _config()
    application = FastAPI(
        lifespan=build_lifespan(
            config,
            primary_database_factory=primary_factory,
            limiter_factory=limiter_factory,
            provider_factory=provider_factory,
            authentication_factory=authentication_factory,
        )
    )

    with TestClient(application):
        assert primary_runtime is not None
        assert application.state.authentication_runtime.config is config
        assert application.state.authentication_runtime.lifecycle_engine is primary_runtime.engine

    assert events == [
        "primary.create",
        "primary.startup",
        "recovery",
        "limiter.create",
        "provider.create",
        "authentication.create",
        "authentication.close",
        "provider.close",
        "limiter.close",
        "primary.close",
    ]


def test_provider_startup_failure_closes_the_limiter(environment):
    created: list[FakeLimiter] = []
    primary_factory = FakePrimaryFactory()

    def limiter_factory(config: DormantServerRuntimeConfig) -> FakeLimiter:
        limiter = FakeLimiter(config)
        created.append(limiter)
        return limiter

    def failing_provider(_config: DormantServerRuntimeConfig):
        raise RuntimeError("provider unavailable")

    application = FastAPI(
        lifespan=build_lifespan(
            _config(),
            provider_factory=failing_provider,
            limiter_factory=limiter_factory,
            primary_database_factory=primary_factory,
        )
    )
    with pytest.raises(RuntimeError, match="provider unavailable"):
        with TestClient(application):
            pass

    assert created[0].close_calls == 1
    assert primary_factory.created[0].close_calls == 1
    assert not hasattr(application.state, "authentication_runtime")


def test_provider_shutdown_failure_still_closes_the_limiter(environment):
    created: list[FakeLimiter] = []
    primary_factory = FakePrimaryFactory()

    def limiter_factory(config: DormantServerRuntimeConfig) -> FakeLimiter:
        limiter = FakeLimiter(config)
        created.append(limiter)
        return limiter

    class FailingCloseProvider(FakeProvider):
        def close(self) -> None:
            super().close()
            raise RuntimeError("provider close failed")

    application = FastAPI(
        lifespan=build_lifespan(
            _config(),
            provider_factory=FailingCloseProvider,
            limiter_factory=limiter_factory,
            primary_database_factory=primary_factory,
        )
    )
    runtime = None
    with pytest.raises(RuntimeError, match="provider close failed"):
        with TestClient(application):
            runtime = application.state.authentication_runtime

    assert runtime is not None
    assert "closed=True" in repr(runtime)
    assert created[0].close_calls == 1
    assert primary_factory.created[0].close_calls == 1
    assert not hasattr(application.state, "authentication_runtime")


def test_application_failure_closes_both_server_resources(environment):
    providers: list[FakeProvider] = []
    limiters: list[FakeLimiter] = []
    primary_factory = FakePrimaryFactory()

    def provider_factory(config: DormantServerRuntimeConfig) -> FakeProvider:
        provider = FakeProvider(config)
        providers.append(provider)
        return provider

    def limiter_factory(config: DormantServerRuntimeConfig) -> FakeLimiter:
        limiter = FakeLimiter(config)
        limiters.append(limiter)
        return limiter

    application = FastAPI(
        lifespan=build_lifespan(
            _config(),
            provider_factory=provider_factory,
            limiter_factory=limiter_factory,
            primary_database_factory=primary_factory,
        )
    )
    with pytest.raises(RuntimeError, match="request failed"):
        with TestClient(application):
            raise RuntimeError("request failed")

    assert providers[0].close_calls == 1
    assert limiters[0].close_calls == 1
    assert primary_factory.created[0].close_calls == 1
    assert not hasattr(application.state, "authentication_runtime")


def test_authentication_startup_failure_closes_provider_and_limiter(environment):
    providers: list[FakeProvider] = []
    limiters: list[FakeLimiter] = []
    primary_factory = FakePrimaryFactory()

    def provider_factory(config: DormantServerRuntimeConfig) -> FakeProvider:
        provider = FakeProvider(config)
        providers.append(provider)
        return provider

    def limiter_factory(config: DormantServerRuntimeConfig) -> FakeLimiter:
        limiter = FakeLimiter(config)
        limiters.append(limiter)
        return limiter

    def failing_authentication_factory(_config, _provider, _limiter, _engine):
        raise RuntimeError("authentication unavailable")

    application = FastAPI(
        lifespan=build_lifespan(
            _config(),
            provider_factory=provider_factory,
            limiter_factory=limiter_factory,
            primary_database_factory=primary_factory,
            authentication_factory=failing_authentication_factory,
        )
    )
    with pytest.raises(RuntimeError, match="authentication unavailable"):
        with TestClient(application):
            pass

    assert providers[0].close_calls == 1
    assert limiters[0].close_calls == 1
    assert primary_factory.created[0].close_calls == 1
    assert not hasattr(application.state, "authentication_runtime")


def test_primary_database_startup_failure_prevents_other_server_resources(environment):
    provider = Mock(side_effect=AssertionError("provider must not start"))
    limiter = Mock(side_effect=AssertionError("limiter must not start"))
    created: list[FakePrimaryDatabase] = []

    class FailingStartupPrimary(FakePrimaryDatabase):
        @contextmanager
        def startup_session(self):
            self.startup_calls += 1
            raise RuntimeError("primary database unavailable")
            yield  # pragma: no cover

    def failing_primary(config):
        runtime = FailingStartupPrimary(config)
        created.append(runtime)
        return runtime

    application = FastAPI(
        lifespan=build_lifespan(
            _config(),
            provider_factory=provider,
            limiter_factory=limiter,
            primary_database_factory=failing_primary,
        )
    )
    with pytest.raises(RuntimeError, match="primary database unavailable"):
        with TestClient(application):
            pass

    provider.assert_not_called()
    limiter.assert_not_called()
    assert created[0].startup_calls == 1
    assert created[0].close_calls == 1
    assert not hasattr(application.state, "primary_database_runtime")


def test_authentication_shutdown_failure_still_closes_provider_and_limiter(environment):
    providers: list[FakeProvider] = []
    limiters: list[FakeLimiter] = []
    authenticators: list[FakeAuthentication] = []
    primary_factory = FakePrimaryFactory()

    def provider_factory(config):
        provider = FakeProvider(config)
        providers.append(provider)
        return provider

    def limiter_factory(config):
        limiter = FakeLimiter(config)
        limiters.append(limiter)
        return limiter

    class FailingCloseAuthentication(FakeAuthentication):
        def close(self) -> None:
            super().close()
            raise RuntimeError("authentication close failed")

    def authentication_factory(config, provider, limiter, lifecycle_engine):
        runtime = FailingCloseAuthentication(config, provider, limiter, lifecycle_engine)
        authenticators.append(runtime)
        return runtime

    application = FastAPI(
        lifespan=build_lifespan(
            _config(),
            provider_factory=provider_factory,
            limiter_factory=limiter_factory,
            primary_database_factory=primary_factory,
            authentication_factory=authentication_factory,
        )
    )

    with pytest.raises(RuntimeError, match="authentication close failed"):
        with TestClient(application):
            pass

    assert authenticators[0].close_calls == 1
    assert providers[0].close_calls == 1
    assert limiters[0].close_calls == 1
    assert primary_factory.created[0].close_calls == 1
    assert not hasattr(application.state, "authentication_runtime")


def test_local_lifespan_uses_only_local_database_resources(
    environment, monkeypatch, recovered_sessions
):
    import app.main

    initialized = Mock()
    local_session = object()

    @contextmanager
    def local_sessions():
        yield local_session

    primary_factory = Mock(side_effect=AssertionError("server database must not start"))
    monkeypatch.setattr(app.main, "initialize_database", initialized)
    monkeypatch.setattr(app.main, "SessionLocal", local_sessions)
    application = FastAPI(
        lifespan=build_lifespan(primary_database_factory=primary_factory)
    )

    with TestClient(application):
        assert not hasattr(application.state, "primary_database_runtime")

    initialized.assert_called_once_with()
    primary_factory.assert_not_called()
    assert recovered_sessions == [local_session]


def test_default_local_application_never_creates_an_oidc_provider(environment):
    application = create_app()

    with TestClient(application, base_url="http://localhost"):
        assert not hasattr(application.state, "oidc_provider")
        assert not hasattr(application.state, "rate_limiter")
        assert not hasattr(application.state, "primary_database_runtime")
        assert not hasattr(application.state, "authentication_runtime")
        assert not any(
            getattr(route, "path", "").startswith("/api/auth") for route in application.routes
        )
