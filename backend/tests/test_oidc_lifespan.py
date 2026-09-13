from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.config import DormantServerIdentityConfig
from app.main import build_lifespan, create_app


def _config() -> DormantServerIdentityConfig:
    return DormantServerIdentityConfig(
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
    )


class FakeProvider:
    def __init__(self, config: DormantServerIdentityConfig) -> None:
        self.config = config
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


def test_configured_lifespan_owns_exactly_one_provider_per_application(environment):
    created: list[FakeProvider] = []

    def factory(config: DormantServerIdentityConfig) -> FakeProvider:
        provider = FakeProvider(config)
        created.append(provider)
        return provider

    applications = [
        FastAPI(lifespan=build_lifespan(_config(), provider_factory=factory)) for _ in range(2)
    ]

    for application in applications:
        with TestClient(application) as client:
            first = application.state.oidc_provider
            assert client.get("/").status_code == 404
            assert application.state.oidc_provider is first
            assert first.config is not None
        assert not hasattr(application.state, "oidc_provider")

    assert len(created) == 2
    assert created[0] is not created[1]
    assert [provider.close_calls for provider in created] == [1, 1]


def test_default_local_application_never_creates_an_oidc_provider(environment):
    application = create_app()

    with TestClient(application, base_url="http://localhost"):
        assert not hasattr(application.state, "oidc_provider")
