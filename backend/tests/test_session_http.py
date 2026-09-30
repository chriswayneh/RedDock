from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie

import pytest
from sqlalchemy import func, select

from app.browser_security import CSRF_HEADER_NAME, SESSION_COOKIE_NAME
from app.database import DATABASE_REQUEST_BINDING_STATE, DatabaseRequestBinding
from app.models import BrowserSession, Membership, Organization, SecurityAuditEvent, User
from app.rate_limits import RateLimitDecision, RateLimitUnavailable
from app.request_authentication import AUTHENTICATION_REQUEST_BINDING_STATE
from app.session_auth import SessionUnavailable, create_browser_session, use_browser_session
from tests.test_authentication import authentication_http_setup as authentication_http_setup
from tests.test_authentication import authentication_setup as authentication_setup


@pytest.fixture()
def session_http_setup(authentication_http_setup, monkeypatch):
    client, application, setup = authentication_http_setup
    database, _config, _limiter, _provider, _runtime, membership_id = setup
    now = datetime.now(UTC)
    monkeypatch.setattr("app.session_auth._now", lambda: now)
    issued = create_browser_session(database.engine, membership_id, now=now - timedelta(hours=2))
    with database.SessionLocal.begin() as session:
        session.get(BrowserSession, issued.session_id).last_seen_at = now - timedelta(minutes=10)
    headers = {
        "Cookie": f"{SESSION_COOKIE_NAME}={issued.token}",
        "Origin": "https://reddock.example", CSRF_HEADER_NAME: issued.csrf_token,
    }
    return client, application, setup, issued, headers, now


def _records(database):
    with database.SessionLocal() as session:
        return list(session.scalars(select(BrowserSession).order_by(BrowserSession.id)))


def test_renew_rotates_both_proofs_once_and_preserves_absolute_expiry(session_http_setup):
    client, _app, setup, issued, headers, now = session_http_setup
    response = client.post("/api/auth/renew", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["rotated"] is True
    assert datetime.fromisoformat(body["expires_at"]) == issued.expires_at
    assert body["csrf_token"] != issued.csrf_token
    replacement = client.cookies.get(SESSION_COOKIE_NAME)
    assert replacement != issued.token and replacement not in response.text
    cookie = SimpleCookie(response.headers["set-cookie"])[SESSION_COOKIE_NAME]
    assert 21_590 <= int(cookie["max-age"]) <= 21_600
    assert cookie["secure"] and cookie["httponly"] and cookie["samesite"] == "lax"
    assert cookie["path"] == "/" and not cookie["domain"] and cookie["expires"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert setup[2].calls[-1][1].value == str(setup[5])
    assert use_browser_session(
        setup[0].engine, replacement, csrf_token=body["csrf_token"], now=now,
    ) is not None
    records = _records(setup[0])
    assert len(records) == 2 and records[0].replaced_at is not None
    # A stale response never overwrites the cookie won by another renewal.
    stale = client.post("/api/auth/renew", headers=headers)
    assert stale.status_code == 401 and "set-cookie" not in stale.headers
    assert client.cookies.get(SESSION_COOKIE_NAME) == replacement
    assert len(_records(setup[0])) == 2


def test_early_renewal_touches_without_rotating_or_resetting_cookie(session_http_setup):
    client, _app, setup, issued, headers, now = session_http_setup
    with setup[0].SessionLocal.begin() as session:
        session.get(BrowserSession, issued.session_id).token_issued_at = now - timedelta(minutes=20)
    response = client.post("/api/auth/renew", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "rotated": False, "csrf_token": None, "expires_at": issued.expires_at.isoformat(),
    }
    assert "set-cookie" not in response.headers
    record, = _records(setup[0])
    assert record.last_seen_at.replace(tzinfo=UTC) == now
    assert record.replaced_at is None


@pytest.mark.parametrize("operation", ["renew", "logout"])
@pytest.mark.parametrize("fault", [
    "no_origin", "wrong_origin", "duplicate_origin", "no_csrf", "wrong_csrf",
    "duplicate_csrf", "no_cookie", "duplicate_cookie", "untrusted_ingress",
])
def test_bad_browser_proofs_do_not_mutate_or_consume_admission(
    session_http_setup, operation, fault,
):
    client, _app, setup, issued, original_headers, now = session_http_setup
    headers = dict(original_headers)
    if fault == "no_origin":
        headers.pop("Origin")
    elif fault == "wrong_origin":
        headers["Origin"] = "https://other.example"
    elif fault == "no_csrf":
        headers.pop(CSRF_HEADER_NAME)
    elif fault == "wrong_csrf":
        headers[CSRF_HEADER_NAME] = "x" * 43
    elif fault == "no_cookie":
        headers.pop("Cookie")
    elif fault == "duplicate_cookie":
        headers["Cookie"] += "; " + headers["Cookie"]
    elif fault == "untrusted_ingress":
        headers["X-Forwarded-Proto"] = "http"
    elif fault.startswith("duplicate_"):
        name = "Origin" if fault == "duplicate_origin" else CSRF_HEADER_NAME
        headers = [*headers.items(), (name, headers[name])]
    response = client.post(f"/api/auth/{operation}", headers=headers)
    assert response.status_code in {400, 401}
    assert "set-cookie" not in response.headers
    assert setup[2].calls == []
    record, = _records(setup[0])
    assert record.revoked_at is None and record.replaced_at is None
    assert record.last_seen_at.replace(tzinfo=UTC) == now - timedelta(minutes=10)


@pytest.mark.parametrize("operation", ["renew", "logout"])
@pytest.mark.parametrize("fault", ["missing", "mismatched", "local", "closed"])
def test_session_routes_require_exact_live_capability(session_http_setup, operation, fault):
    client, app, setup, _issued, headers, _now = session_http_setup
    if fault == "missing":
        delattr(app.state, AUTHENTICATION_REQUEST_BINDING_STATE)
    elif fault == "closed":
        setup[4].close()
    else:
        binding = DatabaseRequestBinding(
            "local" if fault == "local" else "server", setup[0].SessionLocal,
        )
        setattr(app.state, DATABASE_REQUEST_BINDING_STATE, binding)
    response = client.post(f"/api/auth/{operation}", headers=headers)
    assert response.status_code == 401 and "set-cookie" not in response.headers
    assert setup[2].calls == []


@pytest.mark.parametrize("operation", ["renew", "logout"])
@pytest.mark.parametrize("failure", ["denied", "limiter_unavailable", "store_unavailable"])
def test_failed_admission_or_commit_preserves_cookie_and_session(
    session_http_setup, monkeypatch, operation, failure,
):
    client, _app, setup, _issued, headers, now = session_http_setup
    limiter = setup[2]
    if failure == "denied":
        limiter.decision = RateLimitDecision(allowed=False, retry_after_seconds=19)
    elif failure == "limiter_unavailable":
        limiter.error = RateLimitUnavailable("private database error")
    else:
        def unavailable(*args, **kwargs):
            raise SessionUnavailable("private database error")
        name = "use_browser_session" if operation == "renew" else "logout_proven_browser_session"
        monkeypatch.setattr(f"app.authentication.{name}", unavailable)
    response = client.post(f"/api/auth/{operation}", headers=headers)
    assert response.status_code == (429 if failure == "denied" else 401)
    assert response.json() == {"detail": "Authentication failed"}
    assert response.headers.get("retry-after") == ("19" if failure == "denied" else None)
    assert "set-cookie" not in response.headers
    record, = _records(setup[0])
    assert record.revoked_at is None and record.replaced_at is None
    assert record.last_seen_at.replace(tzinfo=UTC) == now - timedelta(minutes=10)


@pytest.mark.parametrize(
    "change", ["membership", "user", "issuer", "organization", "expiry", "idle"],
)
def test_renew_rechecks_identity_and_expiry_after_admission(
    session_http_setup, monkeypatch, change,
):
    client, _app, setup, issued, headers, now = session_http_setup
    database, _config, limiter, _provider, _runtime, membership_id = setup

    def admit_then_change(*args, **kwargs):
        with database.SessionLocal.begin() as session:
            membership = session.get(Membership, membership_id)
            if change == "membership":
                membership.status = "disabled"
            elif change == "user":
                session.get(User, membership.user_id).status = "disabled"
            elif change == "issuer":
                session.get(User, membership.user_id).oidc_issuer = "https://other.example"
            elif change == "organization":
                session.get(Organization, membership.organization_id).slug = "changed-team"
            elif change == "expiry":
                session.get(BrowserSession, issued.session_id).expires_at = now
            else:
                record = session.get(BrowserSession, issued.session_id)
                record.last_seen_at = now - timedelta(hours=1)
        return RateLimitDecision(allowed=True, retry_after_seconds=0)

    monkeypatch.setattr(limiter, "enforce", admit_then_change)
    response = client.post("/api/auth/renew", headers=headers)
    assert response.status_code == 401 and "set-cookie" not in response.headers
    record, = _records(database)
    assert record.replaced_at is None
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(SecurityAuditEvent).where(
            SecurityAuditEvent.action == "session.rotate",
        )) == 0


def test_logout_contains_rotation_after_admission_and_is_idempotent(
    session_http_setup, monkeypatch,
):
    client, _app, setup, issued, headers, now = session_http_setup
    database, _config, limiter, _provider, _runtime, _membership_id = setup
    original_enforce = limiter.enforce

    def rotate_then_admit(*args, **kwargs):
        result = use_browser_session(
            database.engine, issued.token, csrf_token=issued.csrf_token,
            rotate_if_due=True, now=now,
        )
        assert result.replacement is not None
        return original_enforce(*args, **kwargs)

    monkeypatch.setattr(limiter, "enforce", rotate_then_admit)
    response = client.post("/api/auth/logout", headers=headers)
    assert response.status_code == 204 and not response.content
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 2 and all("Max-Age=0" in cookie for cookie in cookies)
    assert response.headers["cache-control"] == "no-store"
    records = _records(database)
    assert len(records) == 2 and all(record.revoked_at is not None for record in records)
    monkeypatch.setattr(limiter, "enforce", original_enforce)
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(SecurityAuditEvent).where(
            SecurityAuditEvent.action == "session.replay",
        )) == 1


@pytest.mark.parametrize("change", ["membership", "issuer", "organization"])
def test_logout_rechecks_boundary_but_can_revoke_disabled_membership(
    session_http_setup, monkeypatch, change,
):
    client, _app, setup, _issued, headers, _now = session_http_setup
    database, _config, limiter, _provider, _runtime, membership_id = setup

    def change_then_admit(*args, **kwargs):
        with database.SessionLocal.begin() as session:
            membership = session.get(Membership, membership_id)
            if change == "membership":
                membership.status = "disabled"
            elif change == "issuer":
                session.get(User, membership.user_id).oidc_issuer = "https://other.example"
            else:
                session.get(Organization, membership.organization_id).slug = "other-team"
        return RateLimitDecision(allowed=True, retry_after_seconds=0)

    monkeypatch.setattr(limiter, "enforce", change_then_admit)
    response = client.post("/api/auth/logout", headers=headers)
    assert response.status_code == (204 if change == "membership" else 401)
    record, = _records(database)
    assert (record.revoked_at is not None) == (change == "membership")


def test_session_adapters_remain_absent_from_local_app(client):
    for operation in ("renew", "logout"):
        assert client.post(f"/api/auth/{operation}").status_code == 405
