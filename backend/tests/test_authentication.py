from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretBytes, SecretStr
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.authentication import AuthenticationFailure, AuthenticationRuntime
from app.authentication_http import build_authentication_router
from app.browser_security import OIDC_TRANSACTION_COOKIE_NAME, SESSION_COOKIE_NAME
from app.config import DormantServerRuntimeConfig
from app.database import DATABASE_REQUEST_BINDING_STATE, DatabaseRequestBinding
from app.models import (
    BrowserSession,
    Membership,
    OidcLoginAttempt,
    Organization,
    SecurityAuditEvent,
    User,
)
from app.oidc import OidcError, VerifiedIdentity
from app.rate_limits import RateLimitDecision, RateLimitUnavailable
from app.request_authentication import (
    AUTHENTICATION_REQUEST_BINDING_STATE,
    AuthenticationRequestBinding,
)
from app.trusted_ingress import TrustedIngressMiddleware


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


class FakeLimiter:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.decision = RateLimitDecision(allowed=True, retry_after_seconds=0)
        self.error: Exception | None = None

    def enforce(self, plan, *, subject, now=None):
        self.calls.append((plan, subject, now))
        if self.error is not None:
            raise self.error
        return self.decision


class FakeProvider:
    def __init__(self, config: DormantServerRuntimeConfig) -> None:
        self.config = config
        self.calls: list[object] = []
        self.discovery_error: Exception | None = None
        self.exchange_error: Exception | None = None
        self.validation_error: Exception | None = None
        self.identity = VerifiedIdentity(
            issuer=config.oidc_issuer,
            subject="provisioned-subject",
        )

    def discovery(self):
        self.calls.append("discovery")
        if self.discovery_error is not None:
            raise self.discovery_error
        return object()

    def authorization_url(self, attempt) -> str:
        self.calls.append(("authorization", attempt.pkce_challenge))
        return f"https://identity.example/authorize?state={attempt.state}"

    def exchange_code(self, *, code: str, pkce_verifier: str) -> str:
        self.calls.append(("exchange", code, pkce_verifier))
        if self.exchange_error is not None:
            raise self.exchange_error
        return "signed-id-token"

    def validate_id_token(self, token: str, *, expected_nonce_hash: str):
        self.calls.append(("validate", token, expected_nonce_hash))
        if self.validation_error is not None:
            raise self.validation_error
        return self.identity


@pytest.fixture()
def authentication_setup(environment):
    from app import database

    database.initialize_database()
    config = _config()
    with database.SessionLocal() as session:
        organization = Organization(slug=config.organization_slug, name="Server Team")
        user = User(
            oidc_issuer=config.oidc_issuer,
            oidc_subject="provisioned-subject",
            display_name="Provisioned User",
            status="active",
        )
        session.add_all([organization, user])
        session.flush()
        membership = Membership(
            organization_id=organization.id,
            user_id=user.id,
            role="operator",
            status="active",
        )
        session.add(membership)
        session.commit()
        membership_id = membership.id
    limiter = FakeLimiter()
    provider = FakeProvider(config)
    runtime = AuthenticationRuntime(config, provider, limiter, database.engine)
    return database, config, limiter, provider, runtime, membership_id


def test_login_is_limited_before_provider_and_persists_one_browser_bound_attempt(
    authentication_setup,
):
    database, _config, limiter, provider, runtime, _membership_id = authentication_setup
    checked_at = datetime(2026, 9, 13, 20, 0, tzinfo=UTC)

    challenge = runtime.begin_login("203.0.113.10", now=checked_at)

    assert limiter.calls[0][0].action.value == "oidc.login"
    assert limiter.calls[0][1].value == "203.0.113.10"
    assert provider.calls[0] == "discovery"
    assert provider.calls[1][0] == "authorization"
    state = parse_qs(urlsplit(challenge.authorization_url).query)["state"][0]
    with database.SessionLocal() as session:
        attempt = session.scalar(select(OidcLoginAttempt))
        assert attempt is not None
        assert attempt.state_hash != state
        assert attempt.browser_token_hash != challenge.browser_token
    rendered = repr(challenge)
    assert state not in rendered
    assert challenge.browser_token not in rendered
    assert challenge.authorization_url not in rendered


@pytest.mark.parametrize("unavailable", [False, True])
def test_login_limiter_failure_makes_no_provider_call_or_attempt(
    authentication_setup,
    unavailable: bool,
):
    database, _config, limiter, provider, runtime, _membership_id = authentication_setup
    if unavailable:
        limiter.error = RateLimitUnavailable("database detail that must not escape")
    else:
        limiter.decision = RateLimitDecision(allowed=False, retry_after_seconds=37)

    with pytest.raises(AuthenticationFailure, match="Authentication failed") as failure:
        runtime.begin_login("203.0.113.10")

    assert failure.value.__cause__ is None
    assert failure.value.retry_after_seconds == (None if unavailable else 37)
    assert provider.calls == []
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(OidcLoginAttempt)) == 0


def test_provider_discovery_failure_does_not_leave_an_attempt(authentication_setup):
    database, _config, _limiter, provider, runtime, _membership_id = authentication_setup
    provider.discovery_error = OidcError("private provider detail")

    with pytest.raises(AuthenticationFailure, match="Authentication failed") as failure:
        runtime.begin_login("203.0.113.10")

    assert failure.value.__cause__ is None
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(OidcLoginAttempt)) == 0


def test_callback_consumes_attempt_then_issues_hash_only_audited_session(
    authentication_setup,
):
    database, _config, limiter, provider, runtime, membership_id = authentication_setup
    checked_at = datetime(2026, 9, 13, 20, 0, tzinfo=UTC)
    challenge = runtime.begin_login("203.0.113.10", now=checked_at)
    state = parse_qs(urlsplit(challenge.authorization_url).query)["state"][0]

    issued = runtime.complete_callback(
        "203.0.113.10",
        state=state,
        browser_token=challenge.browser_token,
        code="authorization-code",
        now=checked_at,
    )

    assert limiter.calls[-1][0].action.value == "oidc.callback"
    assert provider.calls[-2][0] == "exchange"
    assert provider.calls[-1][0] == "validate"
    assert provider.calls[-1][1] == "signed-id-token"
    assert len(provider.calls[-1][2]) == 64
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(OidcLoginAttempt)) == 0
        stored = session.scalar(select(BrowserSession))
        assert stored is not None
        assert stored.membership_id == membership_id
        assert stored.token_hash != issued.token
        assert stored.csrf_token_hash != issued.csrf_token
        event = session.scalar(
            select(SecurityAuditEvent).where(SecurityAuditEvent.action == "session.issue")
        )
        assert event is not None
        assert event.actor_membership_id == membership_id
    rendered = repr(issued)
    assert issued.token not in rendered
    assert issued.csrf_token not in rendered


def test_provider_failure_burns_attempt_and_never_issues_a_session(authentication_setup):
    database, _config, _limiter, provider, runtime, _membership_id = authentication_setup
    challenge = runtime.begin_login("203.0.113.10")
    state = parse_qs(urlsplit(challenge.authorization_url).query)["state"][0]
    provider.exchange_error = OidcError("token endpoint body that must not escape")

    for _ in range(2):
        with pytest.raises(AuthenticationFailure, match="Authentication failed") as failure:
            runtime.complete_callback(
                "203.0.113.10",
                state=state,
                browser_token=challenge.browser_token,
                code="authorization-code",
            )
        assert failure.value.__cause__ is None

    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(OidcLoginAttempt)) == 0
        assert session.scalar(select(func.count()).select_from(BrowserSession)) == 0
    exchange_calls = [
        call for call in provider.calls if isinstance(call, tuple) and call[0] == "exchange"
    ]
    assert len(exchange_calls) == 1
    with database.SessionLocal() as session:
        events = list(
            session.scalars(
                select(SecurityAuditEvent).where(
                    SecurityAuditEvent.reason_code == "provider_exchange_failed"
                )
            )
        )
    assert len(events) == 1


def test_id_token_failure_burns_attempt_and_records_bounded_denial(
    authentication_setup,
):
    database, _config, _limiter, provider, runtime, _membership_id = authentication_setup
    challenge = runtime.begin_login("203.0.113.10")
    state = parse_qs(urlsplit(challenge.authorization_url).query)["state"][0]
    provider.validation_error = OidcError("private claims detail")

    with pytest.raises(AuthenticationFailure, match="Authentication failed") as failure:
        runtime.complete_callback(
            "203.0.113.10",
            state=state,
            browser_token=challenge.browser_token,
            code="authorization-code",
        )

    assert failure.value.__cause__ is None
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(OidcLoginAttempt)) == 0
        assert session.scalar(select(func.count()).select_from(BrowserSession)) == 0
        event = session.scalar(
            select(SecurityAuditEvent).where(SecurityAuditEvent.reason_code == "id_token_invalid")
        )
        assert event is not None


def test_audit_store_failure_does_not_change_generic_provider_denial(
    authentication_setup,
    monkeypatch,
):
    import app.authentication as authentication_module

    database, _config, _limiter, provider, runtime, _membership_id = authentication_setup
    challenge = runtime.begin_login("203.0.113.10")
    state = parse_qs(urlsplit(challenge.authorization_url).query)["state"][0]
    provider.exchange_error = OidcError("private provider detail")

    def fail_audit(*_args, **_kwargs):
        raise SQLAlchemyError("private audit store detail")

    monkeypatch.setattr(authentication_module, "append_security_event", fail_audit)

    with pytest.raises(AuthenticationFailure, match="Authentication failed") as failure:
        runtime.complete_callback(
            "203.0.113.10",
            state=state,
            browser_token=challenge.browser_token,
            code="authorization-code",
        )

    assert failure.value.__cause__ is None
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(OidcLoginAttempt)) == 0
        assert session.scalar(select(func.count()).select_from(BrowserSession)) == 0


def test_unprovisioned_identity_fails_generically_and_records_bounded_denial(
    authentication_setup,
):
    database, _config, _limiter, provider, runtime, _membership_id = authentication_setup
    provider.identity = VerifiedIdentity(
        issuer=provider.config.oidc_issuer,
        subject="not-provisioned",
    )
    challenge = runtime.begin_login("203.0.113.10")
    state = parse_qs(urlsplit(challenge.authorization_url).query)["state"][0]

    with pytest.raises(AuthenticationFailure, match="Authentication failed") as failure:
        runtime.complete_callback(
            "203.0.113.10",
            state=state,
            browser_token=challenge.browser_token,
            code="authorization-code",
        )

    assert failure.value.__cause__ is None
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(BrowserSession)) == 0
        event = session.scalar(
            select(SecurityAuditEvent).where(SecurityAuditEvent.action == "authentication.deny")
        )
        assert event is not None
        assert event.reason_code == "identity_not_provisioned"


@pytest.mark.parametrize("unavailable", [False, True])
def test_callback_limiter_failure_preserves_attempt_and_skips_provider(
    authentication_setup,
    unavailable: bool,
):
    database, _config, limiter, provider, runtime, _membership_id = authentication_setup
    challenge = runtime.begin_login("203.0.113.10")
    state = parse_qs(urlsplit(challenge.authorization_url).query)["state"][0]
    provider_call_count = len(provider.calls)
    if unavailable:
        limiter.error = RateLimitUnavailable("private limiter detail")
    else:
        limiter.decision = RateLimitDecision(allowed=False, retry_after_seconds=11)

    with pytest.raises(AuthenticationFailure) as failure:
        runtime.complete_callback(
            "203.0.113.10",
            state=state,
            browser_token=challenge.browser_token,
            code="authorization-code",
        )

    assert failure.value.__cause__ is None
    assert failure.value.retry_after_seconds == (None if unavailable else 11)
    assert len(provider.calls) == provider_call_count
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(OidcLoginAttempt)) == 1


@pytest.mark.parametrize(
    ("state", "browser_token", "code"),
    [
        (None, "a" * 43, "code"),
        ("a" * 43, 7, "code"),
        ("short", "a" * 43, "code"),
        ("a" * 43, "short", "code"),
        ("a" * 43, "b" * 43, None),
        ("a" * 43, "b" * 43, "bad\ncode"),
    ],
)
def test_malformed_callback_values_are_limited_but_skip_provider_and_database(
    authentication_setup,
    state,
    browser_token,
    code,
):
    _database, _config, limiter, provider, runtime, _membership_id = authentication_setup
    limiter_call_count = len(limiter.calls)
    provider_call_count = len(provider.calls)

    with pytest.raises(AuthenticationFailure, match="Authentication failed") as failure:
        runtime.complete_callback(
            "203.0.113.10",
            state=state,
            browser_token=browser_token,
            code=code,
        )

    assert failure.value.__cause__ is None
    assert len(limiter.calls) == limiter_call_count + 1
    assert limiter.calls[-1][0].action.value == "oidc.callback"
    assert len(provider.calls) == provider_call_count


def test_session_staging_failure_rolls_back_but_does_not_restore_attempt(
    authentication_setup,
    monkeypatch,
):
    import app.authentication as authentication_module

    database, _config, _limiter, _provider, runtime, _membership_id = authentication_setup
    challenge = runtime.begin_login("203.0.113.10")
    state = parse_qs(urlsplit(challenge.authorization_url).query)["state"][0]
    original = authentication_module.issue_browser_session

    def fail_after_staging(session, membership_id, *, now=None):
        original(session, membership_id, now=now)
        raise SQLAlchemyError("private database detail")

    monkeypatch.setattr(authentication_module, "issue_browser_session", fail_after_staging)

    with pytest.raises(AuthenticationFailure, match="Authentication failed") as failure:
        runtime.complete_callback(
            "203.0.113.10",
            state=state,
            browser_token=challenge.browser_token,
            code="authorization-code",
        )

    assert failure.value.__cause__ is None
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(OidcLoginAttempt)) == 0
        assert session.scalar(select(func.count()).select_from(BrowserSession)) == 0
        assert (
            session.scalar(
                select(func.count())
                .select_from(SecurityAuditEvent)
                .where(SecurityAuditEvent.action == "session.issue")
            )
            == 0
        )


def test_closed_runtime_and_unverified_client_values_fail_without_detail(
    authentication_setup,
):
    _database, _config, _limiter, _provider, runtime, _membership_id = authentication_setup

    with pytest.raises(AuthenticationFailure) as invalid_client:
        runtime.begin_login("203.0.113.010")
    assert invalid_client.value.__cause__ is None

    runtime.close()
    limiter_call_count = len(_limiter.calls)
    provider_call_count = len(_provider.calls)
    with pytest.raises(AuthenticationFailure) as closed:
        runtime.begin_login("203.0.113.10")
    assert closed.value.__cause__ is None
    with pytest.raises(AuthenticationFailure):
        runtime.complete_callback(
            "203.0.113.10",
            state="a" * 43,
            browser_token="b" * 43,
            code="code",
        )
    assert len(_limiter.calls) == limiter_call_count
    assert len(_provider.calls) == provider_call_count


@pytest.fixture()
def authentication_http_setup(authentication_setup):
    database, config, limiter, provider, runtime, membership_id = authentication_setup
    application = FastAPI()
    binding = DatabaseRequestBinding("server", database.SessionLocal)
    setattr(application.state, DATABASE_REQUEST_BINDING_STATE, binding)
    setattr(
        application.state, AUTHENTICATION_REQUEST_BINDING_STATE,
        AuthenticationRequestBinding(binding, runtime),
    )
    application.include_router(build_authentication_router())
    application.add_middleware(
        TrustedIngressMiddleware, public_origin=config.public_origin,
        trusted_proxy_cidrs=("10.0.0.5/32",),
    )
    with TestClient(
        application, base_url=config.public_origin, client=("10.0.0.5", 1234),
        follow_redirects=False,
    ) as client:
        client.headers.update({
            "X-Forwarded-For": "203.0.113.10",
            "X-Forwarded-Host": "reddock.example",
            "X-Forwarded-Proto": "https",
        })
        yield client, application, authentication_setup


def _http_login(client):
    response = client.post("/api/auth/login", headers={"Origin": "https://reddock.example"})
    assert response.status_code == 303
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    cookie = response.headers["set-cookie"]
    for attribute in ("Secure", "HttpOnly", "SameSite=lax", "Path=/", "Max-Age=600"):
        assert attribute in cookie
    assert "Domain=" not in cookie
    assert SESSION_COOKIE_NAME not in cookie
    return parse_qs(urlsplit(response.headers["location"]).query)["state"][0]


def test_http_login_callback_issues_session_and_replay_fails(authentication_http_setup):
    client, _application, setup = authentication_http_setup
    database, _config, limiter, provider, runtime, _membership_id = setup
    state = _http_login(client)
    response = client.get("/api/auth/callback", params={
        "state": state, "code": "private-code", "session_state": "provider-extension",
        "next": "https://other.example",
    })
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"csrf_token", "expires_at"}
    bearer = client.cookies.get(SESSION_COOKIE_NAME)
    assert bearer and bearer not in response.text
    assert "private-code" not in response.text and state not in response.text
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 2
    assert "Max-Age=28800" in cookies[0]
    assert "Max-Age=0" in cookies[1]
    for cookie in cookies:
        for attribute in ("Secure", "HttpOnly", "SameSite=lax", "Path=/"):
            assert attribute in cookie
        assert "Domain=" not in cookie
    assert client.cookies.get(OIDC_TRANSACTION_COOKIE_NAME) is None
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "location" not in response.headers
    assert "provider-extension" not in response.text and "other.example" not in response.text
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(BrowserSession)) == 1
    # The issued credentials actually authorize through the existing capability.
    from starlette.requests import Request

    request = Request({
        "type": "http", "method": "POST", "scheme": "https", "path": "/api/test",
        "headers": [
            (b"host", b"reddock.example"), (b"origin", b"https://reddock.example"),
            (b"cookie", f"{SESSION_COOKIE_NAME}={bearer}".encode()),
            (b"x-reddock-csrf", body["csrf_token"].encode()),
        ], "state": {"reddock_client_ip": "203.0.113.10"},
    })
    assert runtime.authorize_browser_request(request) is not None
    exchange_count = len(provider.calls)
    replay = client.get("/api/auth/callback", params={"state": state, "code": "private-code"})
    assert replay.status_code == 401
    assert replay.json() == {"detail": "Authentication failed"}
    assert len(provider.calls) == exchange_count
    assert client.cookies.get(SESSION_COOKIE_NAME) == bearer
    assert limiter.calls[-1][0].action.value == "oidc.callback"


@pytest.mark.parametrize("origin", [None, "null", "https://other.example"])
def test_http_login_rejects_origin_before_admission(authentication_http_setup, origin):
    client, _application, setup = authentication_http_setup
    headers = {} if origin is None else {"Origin": origin}
    response = client.post("/api/auth/login", headers=headers)
    assert response.status_code == 401
    assert "set-cookie" not in response.headers
    assert setup[2].calls == [] and setup[3].calls == []


def test_http_login_rejects_duplicate_origin(authentication_http_setup):
    client, _application, setup = authentication_http_setup
    response = client.post("/api/auth/login", headers=[
        ("Origin", "https://reddock.example"), ("Origin", "https://reddock.example"),
    ])
    assert response.status_code == 401
    assert setup[2].calls == []


@pytest.mark.parametrize("binding_failure", ["missing", "local", "different", "closed"])
def test_http_adapter_requires_exact_live_pair(authentication_http_setup, binding_failure):
    client, application, setup = authentication_http_setup
    if binding_failure == "missing":
        delattr(application.state, AUTHENTICATION_REQUEST_BINDING_STATE)
    elif binding_failure == "closed":
        setup[4].close()
    else:
        mode = "local" if binding_failure == "local" else "server"
        setattr(application.state, DATABASE_REQUEST_BINDING_STATE,
                DatabaseRequestBinding(mode, setup[0].SessionLocal))
    for method, path in (("POST", "/api/auth/login"), ("GET", "/api/auth/callback")):
        response = client.request(method, path, headers={"Origin": "https://reddock.example"})
        assert response.status_code == 401
        assert "set-cookie" not in response.headers
    assert setup[2].calls == [] and setup[3].calls == []


@pytest.mark.parametrize("query", [
    "state=x&state=y&code=c", "state=x&code=c&code=d", "state=x",
    "state=x&code=c&error=access_denied", "error=access_denied&error_description=private",
])
def test_http_malformed_callback_is_limited_and_generic(authentication_http_setup, query):
    client, _application, setup = authentication_http_setup
    _http_login(client)
    provider_count = len(setup[3].calls)
    response = client.get("/api/auth/callback?" + query)
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication failed"}
    assert setup[2].calls[-1][0].action.value == "oidc.callback"
    assert len(setup[3].calls) == provider_count
    assert client.cookies.get(OIDC_TRANSACTION_COOKIE_NAME) is None
    with setup[0].SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(BrowserSession)) == 0


@pytest.mark.parametrize("failure", ["throttled", "limiter", "provider", "membership"])
def test_http_callback_denial_never_sets_bearer(authentication_http_setup, failure):
    client, _application, setup = authentication_http_setup
    database, _config, limiter, provider, _runtime, membership_id = setup
    state = _http_login(client)
    if failure == "throttled":
        limiter.decision = RateLimitDecision(allowed=False, retry_after_seconds=37)
    elif failure == "limiter":
        limiter.error = RateLimitUnavailable("private database detail")
    elif failure == "provider":
        provider.exchange_error = OidcError("private provider detail")
    else:
        with database.SessionLocal() as session:
            session.get(Membership, membership_id).status = "disabled"
            session.commit()
    response = client.get("/api/auth/callback", params={"state": state, "code": "private-code"})
    assert response.status_code == (429 if failure == "throttled" else 401)
    assert response.json() == {"detail": "Authentication failed"}
    assert response.headers.get("retry-after") == ("37" if failure == "throttled" else None)
    assert SESSION_COOKIE_NAME not in response.headers["set-cookie"]
    assert client.cookies.get(OIDC_TRANSACTION_COOKIE_NAME) is None
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(BrowserSession)) == 0


def test_http_adapter_not_registered_in_supported_application(client):
    from app.main import app

    assert not any(getattr(route, "path", "").startswith("/api/auth/") for route in app.routes)
    assert client.get("/api/auth/callback?state=x&code=y").status_code == 404
    assert client.post("/api/auth/login").status_code == 405


@pytest.mark.parametrize("cookie", ["missing", "wrong", "duplicate"])
def test_http_callback_requires_one_matching_browser_cookie(authentication_http_setup, cookie):
    client, _application, setup = authentication_http_setup
    state = _http_login(client)
    browser_token = client.cookies.get(OIDC_TRANSACTION_COOKIE_NAME)
    client.cookies.clear()
    headers = {}
    if cookie == "wrong":
        headers["Cookie"] = f"{OIDC_TRANSACTION_COOKIE_NAME}={'x' * 43}"
    elif cookie == "duplicate":
        headers["Cookie"] = (
            f"{OIDC_TRANSACTION_COOKIE_NAME}={browser_token}; "
            f"{OIDC_TRANSACTION_COOKIE_NAME}={browser_token}"
        )
    provider_count = len(setup[3].calls)
    response = client.get(
        "/api/auth/callback", params={"state": state, "code": "private-code"}, headers=headers,
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication failed"}
    assert setup[2].calls[-1][0].action.value == "oidc.callback"
    assert len(setup[3].calls) == provider_count


def test_http_adapter_without_ingress_marker_denies_before_admission(authentication_setup):
    database, _config, limiter, provider, runtime, _membership_id = authentication_setup
    application = FastAPI()
    binding = DatabaseRequestBinding("server", database.SessionLocal)
    setattr(application.state, DATABASE_REQUEST_BINDING_STATE, binding)
    setattr(application.state, AUTHENTICATION_REQUEST_BINDING_STATE,
            AuthenticationRequestBinding(binding, runtime))
    application.include_router(build_authentication_router())
    with TestClient(application, base_url="https://reddock.example") as client:
        for method, path in (("POST", "/api/auth/login"), ("GET", "/api/auth/callback")):
            response = client.request(method, path, headers={
                "Origin": "https://reddock.example", "X-Forwarded-For": "203.0.113.10",
            })
            assert response.status_code == 401
            assert "set-cookie" not in response.headers
    assert limiter.calls == [] and provider.calls == []


def test_http_login_provider_and_limit_failures_are_generic(authentication_http_setup):
    client, _application, setup = authentication_http_setup
    limiter, provider = setup[2:4]
    provider.discovery_error = OidcError("private provider detail")
    response = client.post("/api/auth/login", headers={"Origin": "https://reddock.example"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication failed"}
    assert "set-cookie" not in response.headers
    provider_count = len(provider.calls)
    limiter.decision = RateLimitDecision(allowed=False, retry_after_seconds=37)
    response = client.post("/api/auth/login", headers={"Origin": "https://reddock.example"})
    assert response.status_code == 429
    assert response.headers["retry-after"] == "37"
    assert response.json() == {"detail": "Authentication failed"}
    assert "set-cookie" not in response.headers
    assert len(provider.calls) == provider_count


def test_callback_session_obeys_route_manifest_outside_supported_app(authentication_setup):
    """Callback access is checked on the product manifest only inside this harness."""
    from app.api import router as product_router
    from app.browser_security import CSRF_HEADER_NAME
    from app.main import app as supported_app

    database, config, _limiter, _provider, runtime, membership_id = authentication_setup
    application = FastAPI()
    binding = DatabaseRequestBinding("server", database.SessionLocal)
    setattr(application.state, DATABASE_REQUEST_BINDING_STATE, binding)
    setattr(
        application.state, AUTHENTICATION_REQUEST_BINDING_STATE,
        AuthenticationRequestBinding(binding, runtime),
    )
    application.include_router(build_authentication_router())
    application.include_router(product_router)
    application.add_middleware(
        TrustedIngressMiddleware, public_origin=config.public_origin,
        trusted_proxy_cidrs=("10.0.0.5/32",),
    )
    with TestClient(
        application, base_url=config.public_origin, client=("10.0.0.5", 1234),
        follow_redirects=False,
    ) as client:
        client.headers.update({
            "X-Forwarded-For": "203.0.113.10",
            "X-Forwarded-Host": "reddock.example",
            "X-Forwarded-Proto": "https",
        })
        assert client.get("/api/dockyards").status_code == 401
        state = _http_login(client)
        issued = client.get("/api/auth/callback", params={"state": state, "code": "code"})
        assert issued.status_code == 200
        assert set(issued.json()) == {"csrf_token", "expires_at"}
        assert client.get("/api/dockyards").json() == []
        assert client.get("/api/dockyards/1/lab/audit").status_code == 403
        missing = client.get("/api/dockyards/1/evidence")
        assert missing.status_code == 404
        assert missing.json()["detail"] == "Dockyard not found"
        with database.SessionLocal() as session:
            session.get(Membership, membership_id).role = "viewer"
            session.commit()
        assert client.get("/api/dockyards").status_code == 200
        denied = client.get("/api/dockyards/1/evidence")
        assert denied.status_code == 403
        assert denied.json()["detail"] == "Permission denied"
        logout = client.post("/api/auth/logout", headers={
            "Origin": config.public_origin,
            CSRF_HEADER_NAME: issued.json()["csrf_token"],
        })
        assert logout.status_code == 204
        assert client.get("/api/dockyards").status_code == 401
    assert not any(
        getattr(route, "path", "").startswith("/api/auth/") for route in supported_app.routes
    )
