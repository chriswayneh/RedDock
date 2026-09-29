from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api import router
from app.browser_security import CSRF_HEADER_NAME, SESSION_COOKIE_NAME
from app.database import DATABASE_REQUEST_BINDING_STATE, DatabaseRequestBinding
from app.main import build_lifespan
from app.models import BrowserSession, Dockyard, Membership, User
from app.rate_limits import RateLimitDecision, RateLimitUnavailable
from app.request_authentication import AUTHENTICATION_REQUEST_BINDING_STATE
from app.session_auth import issue_browser_session
from app.trusted_ingress import TrustedIngressMiddleware
from tests.test_authentication import authentication_setup as authentication_setup


@pytest.fixture()
def request_setup(authentication_setup):
    database, config, limiter, provider, runtime, membership_id = authentication_setup
    provider.close = lambda: None
    limiter.close = lambda: None

    class Primary:
        engine = database.engine
        session = staticmethod(database.SessionLocal)

        def startup_session(self):
            return database.SessionLocal()

        def close(self):
            pass

    application = FastAPI(
        lifespan=build_lifespan(
            config,
            primary_database_factory=lambda _: Primary(),
            provider_factory=lambda _: provider,
            limiter_factory=lambda _: limiter,
            authentication_factory=lambda *_: runtime,
        )
    )
    application.include_router(router)
    application.add_middleware(
        TrustedIngressMiddleware,
        public_origin=config.public_origin,
        trusted_proxy_cidrs=("127.0.0.1/32",),
    )
    with database.SessionLocal() as session:
        issued = issue_browser_session(session, membership_id)
        membership = session.get(Membership, membership_id)
        own = Dockyard(organization_id=membership.organization_id, name="Team workspace")
        other = Dockyard(organization_id=1, name="Other workspace")
        session.add_all([own, other])
        session.commit()
        own_id, other_id = own.id, other.id
    with TestClient(
        application,
        base_url=config.public_origin,
        client=("127.0.0.1", 12345),
        headers={
            "X-Forwarded-For": "203.0.113.10",
            "X-Forwarded-Host": "reddock.example",
            "X-Forwarded-Proto": "https",
        },
    ) as client:
        headers = {
            "Cookie": f"{SESSION_COOKIE_NAME}={issued.token}",
            "Origin": config.public_origin,
            CSRF_HEADER_NAME: issued.csrf_token,
        }
        yield (
            client,
            application,
            database,
            limiter,
            runtime,
            membership_id,
            issued,
            headers,
            own_id,
            other_id,
        )


def test_real_cookie_authority_is_scoped_and_rechecks_role(request_setup):
    client, _, database, limiter, _, membership_id, _, headers, own_id, other_id = request_setup
    response = client.get("/api/dockyards", headers=headers)
    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [own_id]
    assert client.get(f"/api/dockyards/{other_id}", headers=headers).status_code == 404
    assert client.get("/api/dockyards/999999", headers=headers).status_code == 404
    assert (
        client.post("/api/dockyards", headers=headers, json={"name": "Created"}).status_code == 201
    )
    assert limiter.calls[-1][0].action.value == "request.mutation"
    assert limiter.calls[-1][1].value == str(membership_id)
    with database.SessionLocal() as session:
        session.get(Membership, membership_id).role = "viewer"
        session.commit()
    assert client.get("/api/dockyards", headers=headers).status_code == 200
    assert (
        client.post("/api/dockyards", headers=headers, json={"name": "Denied"}).status_code == 403
    )
    assert client.get(f"/api/dockyards/{own_id}/evidence", headers=headers).status_code == 403


@pytest.mark.parametrize(
    "fault",
    ["no_cookie", "wrong_origin", "no_csrf", "bad_csrf", "duplicate_cookie", "duplicate_csrf"],
)
def test_invalid_browser_proofs_never_reach_mutation(request_setup, fault):
    client, _, database, limiter, _, _, issued, headers, _, _ = request_setup
    headers = dict(headers)
    if fault == "no_cookie":
        headers.pop("Cookie")
    elif fault == "wrong_origin":
        headers["Origin"] = "https://other.example"
    elif fault == "no_csrf":
        headers.pop(CSRF_HEADER_NAME)
    elif fault == "bad_csrf":
        headers[CSRF_HEADER_NAME] = "X" * 43
    elif fault == "duplicate_cookie":
        headers["Cookie"] += f"; {SESSION_COOKIE_NAME}={issued.token}"
    elif fault == "duplicate_csrf":
        headers = list(headers.items()) + [(CSRF_HEADER_NAME, issued.csrf_token)]
    response = client.post("/api/dockyards", headers=headers, json={"name": "Must not exist"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}
    assert not limiter.calls
    with database.SessionLocal() as session:
        assert session.scalar(select(Dockyard.id).where(Dockyard.name == "Must not exist")) is None


@pytest.mark.parametrize("fault", ["membership", "user", "issuer", "revoked", "expired", "idle"])
def test_inactive_or_wrong_issuer_identity_cannot_authenticate(request_setup, fault):
    client, _, database, _, _, membership_id, issued, headers, _, _ = request_setup
    with database.SessionLocal() as session:
        membership = session.get(Membership, membership_id)
        browser = session.get(BrowserSession, issued.session_id)
        if fault == "membership":
            membership.status = "disabled"
        elif fault == "user":
            session.get(User, membership.user_id).status = "disabled"
        elif fault == "issuer":
            session.get(User, membership.user_id).oidc_issuer = "https://different.example"
        elif fault == "revoked":
            browser.revoked_at = datetime.now(UTC)
        elif fault == "expired":
            browser.created_at = datetime.now(UTC) - timedelta(hours=2)
            browser.token_issued_at = browser.created_at
            browser.last_seen_at = datetime.now(UTC) - timedelta(minutes=2)
            browser.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        else:
            browser.created_at = datetime.now(UTC) - timedelta(hours=2)
            browser.token_issued_at = browser.created_at
            browser.last_seen_at = datetime.now(UTC) - timedelta(minutes=31)
        session.commit()
    assert client.get("/api/dockyards", headers=headers).status_code == 401


def test_unavailable_limiter_and_durable_denial_are_generic(request_setup):
    client, _, _, limiter, _, _, issued, headers, _, _ = request_setup
    limiter.error = RateLimitUnavailable("private-database-detail")
    response = client.post("/api/dockyards", headers=headers, json={"name": "Denied"})
    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication unavailable"}
    assert issued.token not in response.text and "private-database-detail" not in response.text
    limiter.error = None
    limiter.decision = RateLimitDecision(allowed=False, retry_after_seconds=17)
    response = client.post("/api/dockyards", headers=headers, json={"name": "Denied"})
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "17"


def test_capability_mismatch_and_closed_runtime_never_fall_back(request_setup):
    client, application, _, _, runtime, _, _, headers, _, _ = request_setup
    original = getattr(application.state, DATABASE_REQUEST_BINDING_STATE)
    setattr(
        application.state,
        DATABASE_REQUEST_BINDING_STATE,
        DatabaseRequestBinding("server", original.session_factory),
    )
    assert client.get("/api/dockyards", headers=headers).status_code == 401
    setattr(application.state, DATABASE_REQUEST_BINDING_STATE, original)
    assert hasattr(application.state, AUTHENTICATION_REQUEST_BINDING_STATE)
    runtime.close()
    assert client.get("/api/dockyards", headers=headers).status_code == 503
    assert client.get("/api/health").status_code == 200


def test_untrusted_ingress_and_other_organization_sessions_are_denied(request_setup):
    client, _, database, _, _, membership_id, _, headers, _, _ = request_setup
    assert (
        client.get(
            "/api/dockyards", headers={**headers, "X-Forwarded-Host": "other.example"}
        ).status_code
        == 400
    )
    with database.SessionLocal() as session:
        user_id = session.get(Membership, membership_id).user_id
        other = Membership(organization_id=1, user_id=user_id, role="operator", status="active")
        session.add(other)
        session.flush()
        other_issued = issue_browser_session(session, other.id)
        session.commit()
    assert (
        client.get(
            "/api/dockyards", headers={"Cookie": f"{SESSION_COOKIE_NAME}={other_issued.token}"}
        ).status_code
        == 401
    )
