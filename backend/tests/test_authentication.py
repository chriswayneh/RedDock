from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import SecretBytes, SecretStr
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.authentication import AuthenticationFailure, AuthenticationRuntime
from app.config import DormantServerRuntimeConfig
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
