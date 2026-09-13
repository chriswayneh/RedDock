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


def test_configured_lifespan_owns_exactly_one_provider_per_application(environment):
    created: list[FakeProvider] = []
    limiters: list[FakeLimiter] = []

    def provider_factory(config: DormantServerRuntimeConfig) -> FakeProvider:
        provider = FakeProvider(config)
        created.append(provider)
        return provider

    def limiter_factory(config: DormantServerRuntimeConfig) -> FakeLimiter:
        limiter = FakeLimiter(config)
        limiters.append(limiter)
        return limiter

    applications = [
        FastAPI(
            lifespan=build_lifespan(
                _config(),
                provider_factory=provider_factory,
                limiter_factory=limiter_factory,
            )
        )
        for _ in range(2)
    ]

    for application in applications:
        with TestClient(application) as client:
            first = application.state.oidc_provider
            assert client.get("/").status_code == 404
            assert application.state.oidc_provider is first
            assert application.state.rate_limiter is limiters[-1]
            assert first.config is not None
        assert not hasattr(application.state, "oidc_provider")
        assert not hasattr(application.state, "rate_limiter")

    assert len(created) == 2
    assert len(limiters) == 2
    assert created[0] is not created[1]
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
        )
    )
    with pytest.raises(RuntimeError, match="provider unavailable"):
        with TestClient(application):
            pass

    assert created[0].close_calls == 1
    assert not hasattr(application.state, "rate_limiter")


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
        )
    )
    with pytest.raises(RuntimeError, match="provider close failed"):
        with TestClient(application):
            pass

    assert created[0].close_calls == 1
    assert not hasattr(application.state, "rate_limiter")


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
        )
    )
    with pytest.raises(RuntimeError, match="request failed"):
        with TestClient(application):
            raise RuntimeError("request failed")

    assert providers[0].close_calls == 1
    assert limiters[0].close_calls == 1
    assert not hasattr(application.state, "oidc_provider")
    assert not hasattr(application.state, "rate_limiter")


def test_default_local_application_never_creates_an_oidc_provider(environment):
    application = create_app()

    with TestClient(application, base_url="http://localhost"):
        assert not hasattr(application.state, "oidc_provider")
        assert not hasattr(application.state, "rate_limiter")
