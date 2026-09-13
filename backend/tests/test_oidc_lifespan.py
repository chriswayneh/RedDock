import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretBytes, SecretStr

from app.config import DormantServerRuntimeConfig
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


def _lifecycle_engine():
    from app import database

    return database.engine


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


def test_configured_lifespan_owns_exactly_one_provider_per_application(environment):
    created: list[FakeProvider] = []
    limiters: list[FakeLimiter] = []
    authenticators: list[FakeAuthentication] = []

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
                authentication_factory=authentication_factory,
                lifecycle_engine=_lifecycle_engine(),
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
            assert first.config is not None
            assert not hasattr(application.state, "oidc_provider")
            assert not hasattr(application.state, "rate_limiter")
        assert not hasattr(application.state, "authentication_runtime")

    assert len(created) == 2
    assert len(limiters) == 2
    assert len(authenticators) == 2
    assert created[0] is not created[1]
    assert [runtime.close_calls for runtime in authenticators] == [1, 1]
    assert [provider.close_calls for provider in created] == [1, 1]
    assert [limiter.close_calls for limiter in limiters] == [1, 1]


def test_provider_startup_failure_closes_the_limiter(environment):
    created: list[FakeLimiter] = []

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
            lifecycle_engine=_lifecycle_engine(),
        )
    )
    with pytest.raises(RuntimeError, match="provider unavailable"):
        with TestClient(application):
            pass

    assert created[0].close_calls == 1
    assert not hasattr(application.state, "authentication_runtime")


def test_provider_shutdown_failure_still_closes_the_limiter(environment):
    created: list[FakeLimiter] = []

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
            lifecycle_engine=_lifecycle_engine(),
        )
    )
    runtime = None
    with pytest.raises(RuntimeError, match="provider close failed"):
        with TestClient(application):
            runtime = application.state.authentication_runtime

    assert runtime is not None
    assert "closed=True" in repr(runtime)
    assert created[0].close_calls == 1
    assert not hasattr(application.state, "authentication_runtime")


def test_application_failure_closes_both_server_resources(environment):
    providers: list[FakeProvider] = []
    limiters: list[FakeLimiter] = []

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
            lifecycle_engine=_lifecycle_engine(),
        )
    )
    with pytest.raises(RuntimeError, match="request failed"):
        with TestClient(application):
            raise RuntimeError("request failed")

    assert providers[0].close_calls == 1
    assert limiters[0].close_calls == 1
    assert not hasattr(application.state, "authentication_runtime")


def test_authentication_startup_failure_closes_provider_and_limiter(environment):
    providers: list[FakeProvider] = []
    limiters: list[FakeLimiter] = []

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
            authentication_factory=failing_authentication_factory,
            lifecycle_engine=_lifecycle_engine(),
        )
    )
    with pytest.raises(RuntimeError, match="authentication unavailable"):
        with TestClient(application):
            pass

    assert providers[0].close_calls == 1
    assert limiters[0].close_calls == 1
    assert not hasattr(application.state, "authentication_runtime")


def test_configured_lifespan_requires_an_explicit_lifecycle_engine(environment):
    with pytest.raises(ValueError, match="explicit server lifecycle engine"):
        build_lifespan(_config())


def test_authentication_shutdown_failure_still_closes_provider_and_limiter(environment):
    providers: list[FakeProvider] = []
    limiters: list[FakeLimiter] = []
    authenticators: list[FakeAuthentication] = []

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
            authentication_factory=authentication_factory,
            lifecycle_engine=_lifecycle_engine(),
        )
    )

    with pytest.raises(RuntimeError, match="authentication close failed"):
        with TestClient(application):
            pass

    assert authenticators[0].close_calls == 1
    assert providers[0].close_calls == 1
    assert limiters[0].close_calls == 1
    assert not hasattr(application.state, "authentication_runtime")


def test_default_local_application_never_creates_an_oidc_provider(environment):
    application = create_app()

    with TestClient(application, base_url="http://localhost"):
        assert not hasattr(application.state, "oidc_provider")
        assert not hasattr(application.state, "rate_limiter")
        assert not hasattr(application.state, "authentication_runtime")
        assert not any(
            getattr(route, "path", "").startswith("/api/auth") for route in application.routes
        )
