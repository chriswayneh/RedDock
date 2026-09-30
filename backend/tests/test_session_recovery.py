from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.authorization import permissions_for
from app.browser_security import (
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    SESSION_RECOVERY_HEADER_NAME,
)
from app.models import BrowserSession, Membership, SecurityAuditEvent, User
from app.rate_limits import RateLimitDecision, RateLimitUnavailable
from app.response_security import SECURITY_HEADERS
from app.session_auth import issue_browser_session, rotate_browser_session
from tests.test_authentication import (
    _http_login,
)
from tests.test_authentication import (
    authentication_http_setup as authentication_http_setup,
)
from tests.test_authentication import (
    authentication_setup as authentication_setup,
)


@pytest.fixture()
def recovery(authentication_http_setup):
    client, application, setup = authentication_http_setup
    database, _, _, _, _, membership_id = setup
    with database.SessionLocal() as session:
        issued = issue_browser_session(
            session, membership_id, now=datetime.now(UTC) - timedelta(minutes=10)
        )
        session.commit()
    headers = {
        "Cookie": f"{SESSION_COOKIE_NAME}={issued.token}",
        SESSION_RECOVERY_HEADER_NAME: "recover",
        "Sec-Fetch-Site": "same-origin",
    }
    return client, application, setup, issued, headers


def assert_hardened(response):
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert "set-cookie" not in response.headers
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_recovery_returns_current_permissions_without_extending_session(recovery):
    client, _, setup, issued, headers = recovery
    database, _, limiter, _, _, membership_id = setup
    with database.SessionLocal() as session:
        row = session.get(BrowserSession, issued.session_id)
        before = (row.last_seen_at, row.expires_at, row.token_issued_at, row.generation)
        session.get(Membership, membership_id).role = "auditor"
        session.commit()
        count = session.scalar(select(func.count()).select_from(SecurityAuditEvent))
    response = client.get("/api/auth/session", headers=headers)
    assert response.status_code == 200
    assert_hardened(response)
    body = response.json()
    assert set(body) == {"role", "permissions", "expires_at", "csrf_token"}
    assert body["role"] == "auditor"
    assert body["permissions"] == sorted(permissions_for("auditor"))
    assert body["csrf_token"] == issued.csrf_token
    assert datetime.fromisoformat(body["expires_at"]) == issued.expires_at
    assert issued.token not in response.text
    assert limiter.calls[-1][0].action.value == "request.mutation"
    assert limiter.calls[-1][1].value == str(membership_id)
    with database.SessionLocal() as session:
        row = session.get(BrowserSession, issued.session_id)
        assert (row.last_seen_at, row.expires_at, row.token_issued_at, row.generation) == before
        assert session.scalar(select(func.count()).select_from(SecurityAuditEvent)) == count


def test_callback_cookie_can_recover_proof_and_log_out(authentication_http_setup):
    client, _, setup = authentication_http_setup
    state = _http_login(client)
    assert (
        client.get("/api/auth/callback", params={"state": state, "code": "code"}).status_code == 200
    )
    response = client.get(
        "/api/auth/session",
        headers={
            SESSION_RECOVERY_HEADER_NAME: "recover",
            "Sec-Fetch-Site": "same-origin",
        },
    )
    assert response.status_code == 200
    assert_hardened(response)
    logout = client.post(
        "/api/auth/logout",
        headers={
            "Origin": setup[1].public_origin,
            CSRF_HEADER_NAME: response.json()["csrf_token"],
        },
    )
    assert logout.status_code == 204
    denied = client.get(
        "/api/auth/session",
        headers={
            SESSION_RECOVERY_HEADER_NAME: "recover",
            "Sec-Fetch-Site": "same-origin",
        },
    )
    assert denied.status_code == 401
    assert_hardened(denied)


@pytest.mark.parametrize(
    "fault",
    [
        "missing_header",
        "wrong_header",
        "duplicate_header",
        "missing_fetch_site",
        "cross_site",
        "same_site",
        "navigation",
        "duplicate_fetch_site",
        "wrong_origin",
        "null_origin",
        "duplicate_origin",
        "missing_cookie",
        "wrong_cookie",
        "duplicate_cookie",
    ],
)
def test_recovery_rejects_ambiguous_or_foreign_browser_proofs(recovery, fault):
    client, _, setup, issued, original = recovery
    headers = dict(original)
    if fault == "missing_header":
        headers.pop(SESSION_RECOVERY_HEADER_NAME)
    elif fault == "wrong_header":
        headers[SESSION_RECOVERY_HEADER_NAME] = "anything"
    elif fault == "duplicate_header":
        headers = list(headers.items()) + [(SESSION_RECOVERY_HEADER_NAME, "recover")]
    elif fault == "missing_fetch_site":
        headers.pop("Sec-Fetch-Site")
    elif fault in {"cross_site", "same_site", "navigation"}:
        headers["Sec-Fetch-Site"] = {
            "cross_site": "cross-site",
            "same_site": "same-site",
            "navigation": "none",
        }[fault]
    elif fault == "duplicate_fetch_site":
        headers = list(headers.items()) + [("Sec-Fetch-Site", "same-origin")]
    elif fault == "wrong_origin":
        headers["Origin"] = "https://other.example"
    elif fault == "null_origin":
        headers["Origin"] = "null"
    elif fault == "duplicate_origin":
        headers = list(headers.items()) + [("Origin", setup[1].public_origin)] * 2
    elif fault == "missing_cookie":
        headers.pop("Cookie")
    elif fault == "wrong_cookie":
        headers["Cookie"] = f"{SESSION_COOKIE_NAME}={'X' * 43}"
    else:
        headers["Cookie"] += f"; {SESSION_COOKIE_NAME}={issued.token}"
    response = client.get("/api/auth/session", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication failed"}
    assert_hardened(response)
    assert not setup[2].calls


def test_exact_origin_is_allowed_but_preflight_and_post_are_not(recovery):
    client, _, setup, _, headers = recovery
    assert (
        client.get(
            "/api/auth/session",
            headers={
                **headers,
                "Origin": setup[1].public_origin,
            },
        ).status_code
        == 200
    )
    preflight = client.options(
        "/api/auth/session",
        headers={
            "Origin": "https://other.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": SESSION_RECOVERY_HEADER_NAME,
        },
    )
    assert preflight.status_code == 405
    assert "access-control-allow-origin" not in preflight.headers
    assert client.post("/api/auth/session", headers=headers).status_code == 405


@pytest.mark.parametrize(
    "fault",
    [
        "member",
        "user",
        "issuer",
        "organization",
        "revoked",
        "expired",
        "idle",
        "replaced",
        "csrf_hash",
    ],
)
def test_invalid_retained_identity_or_session_cannot_recover(recovery, fault):
    client, _, setup, issued, headers = recovery
    database, _, limiter, _, _, membership_id = setup
    with database.SessionLocal() as session:
        member = session.get(Membership, membership_id)
        row = session.get(BrowserSession, issued.session_id)
        if fault == "member":
            member.status = "disabled"
        elif fault == "user":
            session.get(User, member.user_id).status = "disabled"
        elif fault == "issuer":
            session.get(User, member.user_id).oidc_issuer = "https://wrong.example"
        elif fault == "organization":
            member.organization_id = 1
        elif fault == "revoked":
            row.revoked_at = datetime.now(UTC)
        elif fault == "expired":
            row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        elif fault == "idle":
            row.created_at = row.token_issued_at = row.last_seen_at = datetime.now(UTC) - timedelta(
                hours=2
            )
        elif fault == "replaced":
            row.replaced_at = datetime.now(UTC)
        else:
            row.csrf_token_hash = "f" * 64
        session.commit()
    response = client.get("/api/auth/session", headers=headers)
    assert response.status_code == 401
    assert_hardened(response)
    assert not limiter.calls


@pytest.mark.parametrize("fault", ["disabled", "revoked", "rotated", "role"])
def test_recovery_rechecks_after_durable_admission(recovery, monkeypatch, fault):
    client, _, setup, issued, headers = recovery
    database, _, limiter, _, _, membership_id = setup
    if fault == "rotated":
        with database.SessionLocal() as session:
            row = session.get(BrowserSession, issued.session_id)
            row.created_at = row.token_issued_at = datetime.now(UTC) - timedelta(hours=2)
            session.commit()
    original = limiter.enforce

    def revoke_during_admission(*args, **kwargs):
        with database.SessionLocal() as session:
            if fault == "disabled":
                session.get(Membership, membership_id).status = "disabled"
            elif fault == "revoked":
                session.get(BrowserSession, issued.session_id).revoked_at = datetime.now(UTC)
            elif fault == "rotated":
                assert rotate_browser_session(session, issued.token, issued.csrf_token)
            else:
                session.get(Membership, membership_id).role = "viewer"
            session.commit()
        return original(*args, **kwargs)

    monkeypatch.setattr(limiter, "enforce", revoke_during_admission)
    response = client.get("/api/auth/session", headers=headers)
    assert response.status_code == (200 if fault == "role" else 401)
    if fault == "role":
        assert response.json()["permissions"] == sorted(permissions_for("viewer"))
    assert_hardened(response)


def test_recovery_limit_failures_preserve_browser_state(recovery):
    client, _, setup, _, headers = recovery
    limiter = setup[2]
    limiter.decision = RateLimitDecision(allowed=False, retry_after_seconds=23)
    response = client.get("/api/auth/session", headers=headers)
    assert response.status_code == 429 and response.headers["Retry-After"] == "23"
    assert_hardened(response)
    limiter.error = RateLimitUnavailable("private connection details")
    response = client.get("/api/auth/session", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication failed"}
    assert_hardened(response)


def test_closed_runtime_cannot_recover(recovery):
    client, _, setup, _, headers = recovery
    setup[4].close()
    response = client.get("/api/auth/session", headers=headers)
    assert response.status_code == 401
    assert not setup[2].calls
    assert_hardened(response)
