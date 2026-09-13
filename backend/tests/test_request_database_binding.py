from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretBytes, SecretStr
from sqlalchemy.orm import Session

from app.authorization import LOCAL_AUTHORIZATION, AuthorizationContext
from app.authorization_dependencies import current_authorization
from app.config import DormantServerRuntimeConfig
from app.database import (
    DATABASE_REQUEST_BINDING_STATE,
    DatabaseRequestBinding,
    get_session,
)


class FakeSession:
    def __init__(self) -> None:
        self.close_calls = 0

    def scalar(self, _statement):
        return 1

    def close(self) -> None:
        self.close_calls += 1


def _session_probe_app() -> FastAPI:
    application = FastAPI()

    @application.get("/session")
    def session_probe(session: Session = Depends(get_session)):
        return {"session_type": type(session).__name__}

    @application.get("/authorization")
    def authorization_probe(
        authorization: AuthorizationContext | None = Depends(current_authorization),
    ):
        return {
            "membership_id": (
                authorization.membership_id if authorization is not None else None
            )
        }

    return application


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
        rate_limit_key=SecretBytes(b"r" * 32),
        rate_limit_database_user="reddock_limiter",
        rate_limit_database_password=SecretStr("limiter-database-secret"),
        server_workers=1,
    )


def test_explicit_local_binding_uses_its_factory_and_local_authorization():
    application = _session_probe_app()
    session = FakeSession()
    factory = Mock(return_value=session)
    setattr(
        application.state,
        DATABASE_REQUEST_BINDING_STATE,
        DatabaseRequestBinding("local", factory),
    )

    with TestClient(application) as client:
        assert client.get("/session").json() == {"session_type": "FakeSession"}
        assert client.get("/authorization").json() == {
            "membership_id": LOCAL_AUTHORIZATION.membership_id
        }

    factory.assert_called_once_with()
    assert session.close_calls == 1


@pytest.mark.parametrize(
    "binding",
    [
        None,
        object(),
        DatabaseRequestBinding("local", None),  # type: ignore[arg-type]
        DatabaseRequestBinding("unexpected", Mock()),  # type: ignore[arg-type]
    ],
)
def test_absent_or_malformed_binding_fails_closed(binding):
    application = _session_probe_app()
    if binding is not None:
        setattr(application.state, DATABASE_REQUEST_BINDING_STATE, binding)

    with TestClient(application) as client:
        response = client.get("/session")
        authorization = client.get("/authorization")

    assert response.status_code == 503
    assert response.json() == {"detail": "Database unavailable"}
    assert authorization.json() == {"membership_id": None}


def test_factory_failure_is_generic_and_never_falls_back_to_global(monkeypatch):
    import app.database

    application = _session_probe_app()
    owned_factory = Mock(side_effect=RuntimeError("database-secret"))
    global_factory = Mock(side_effect=AssertionError("global database fallback"))
    monkeypatch.setattr(app.database, "SessionLocal", global_factory)
    setattr(
        application.state,
        DATABASE_REQUEST_BINDING_STATE,
        DatabaseRequestBinding("server", owned_factory),
    )

    with TestClient(application) as client:
        response = client.get("/session")

    assert response.status_code == 503
    assert response.json() == {"detail": "Database unavailable"}
    assert "database-secret" not in response.text
    owned_factory.assert_called_once_with()
    global_factory.assert_not_called()


def test_configured_protected_request_is_denied_before_database_open(environment):
    from app.api import router

    application = FastAPI()
    application.include_router(router)
    owned_factory = Mock(side_effect=AssertionError("database must remain unopened"))
    setattr(
        application.state,
        DATABASE_REQUEST_BINDING_STATE,
        DatabaseRequestBinding("server", owned_factory),
    )

    with TestClient(application) as client:
        response = client.get("/api/dockyards")

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}
    owned_factory.assert_not_called()


def test_configured_public_readiness_uses_and_closes_owned_session(environment, monkeypatch):
    import app.database
    from app.api import router

    application = FastAPI()
    application.include_router(router)
    session = FakeSession()
    owned_factory = Mock(return_value=session)
    global_factory = Mock(side_effect=AssertionError("global database fallback"))
    monkeypatch.setattr(app.database, "SessionLocal", global_factory)
    setattr(
        application.state,
        DATABASE_REQUEST_BINDING_STATE,
        DatabaseRequestBinding("server", owned_factory),
    )

    with TestClient(application) as client:
        response = client.get("/api/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "service": "reddock-core"}
    owned_factory.assert_called_once_with()
    global_factory.assert_not_called()
    assert session.close_calls == 1


def test_local_lifespan_installs_then_removes_request_binding(environment, monkeypatch):
    import app.main

    recovered: list[object] = []
    monkeypatch.setattr(app.main, "_recover_interrupted_work", recovered.append)
    application = FastAPI(lifespan=app.main.build_lifespan())

    assert not hasattr(application.state, DATABASE_REQUEST_BINDING_STATE)
    with TestClient(application):
        binding = getattr(application.state, DATABASE_REQUEST_BINDING_STATE)
        assert binding == DatabaseRequestBinding("local", app.main.SessionLocal)
    assert not hasattr(application.state, DATABASE_REQUEST_BINDING_STATE)
    assert len(recovered) == 1


def test_configured_lifespan_binds_primary_factory_then_removes_it(
    environment, monkeypatch
):
    import app.main

    class Primary:
        def __init__(self) -> None:
            self.engine = object()
            self.session_calls = 0
            self.close_calls = 0

        @contextmanager
        def startup_session(self) -> Iterator[object]:
            yield object()

        def session(self):
            self.session_calls += 1
            return FakeSession()

        def close(self) -> None:
            self.close_calls += 1

    primary = Primary()
    limiter = Mock()
    provider = Mock()
    authentication = Mock()
    monkeypatch.setattr(app.main, "_recover_interrupted_work", lambda _session: None)
    application = FastAPI(
        lifespan=app.main.build_lifespan(
            _server_config(),
            primary_database_factory=lambda _config: primary,
            limiter_factory=lambda _config: limiter,
            provider_factory=lambda _config: provider,
            authentication_factory=lambda *_args: authentication,
        )
    )

    assert not hasattr(application.state, DATABASE_REQUEST_BINDING_STATE)
    with TestClient(application):
        binding = getattr(application.state, DATABASE_REQUEST_BINDING_STATE)
        assert binding.mode == "server"
        assert binding.session_factory.__self__ is primary
        assert binding.session_factory.__func__ is Primary.session
    assert not hasattr(application.state, DATABASE_REQUEST_BINDING_STATE)
    assert primary.close_calls == 1
