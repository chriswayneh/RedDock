from dataclasses import replace

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from app import team_administration as team
from app.browser_security import CSRF_HEADER_NAME, SESSION_COOKIE_NAME
from app.database import DATABASE_REQUEST_BINDING_STATE, DatabaseRequestBinding
from app.models import Membership, SecurityAuditEvent, User
from app.rate_limits import RateLimitDecision, RateLimitUnavailable
from app.response_security import SECURITY_HEADERS
from app.session_auth import issue_browser_session
from app.team_administration_http import TEAM_ROUTE_PERMISSIONS, build_team_administration_router
from app.workflow_requests import WORKFLOW_REQUEST_BINDING_STATE, WorkflowRequestBinding
from tests.test_authenticated_requests import request_setup as request_setup
from tests.test_authentication import authentication_setup as authentication_setup


@pytest.fixture()
def team_http(request_setup):
    client, application, database, _, _, membership_id, _, _, _, _ = request_setup
    application.include_router(build_team_administration_router())
    with database.SessionLocal() as session:
        session.get(Membership, membership_id).role = "owner"
        session.commit()
    return request_setup


def provision(client, headers, subject="exact-subject", role="operator"):
    return client.post(
        "/api/team/members",
        headers=headers,
        json={
            "subject": subject,
            "display_name": "New Member",
            "role": role,
        },
    )


def assert_hardened(response):
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    for key, value in SECURITY_HEADERS.items():
        assert response.headers[key] == value
    assert "set-cookie" not in response.headers


def test_admin_endpoints_are_unregistered_and_manifest_complete():
    from app.api import router
    from app.main import app

    routes = build_team_administration_router().routes
    assert {(method, route.path) for route in routes for method in route.methods} == set(
        TEAM_ROUTE_PERMISSIONS
    )
    assert not any(route.path.startswith("/api/team") for route in router.routes)
    assert not any(getattr(route, "path", "").startswith("/api/team") for route in app.routes)


def test_provision_roster_and_access_change_use_real_authority(team_http):
    client, _, database, limiter, _, actor_id, _, headers, _, _ = team_http
    created = provision(client, headers)
    assert created.status_code == 201
    member = created.json()
    assert member["subject"] == "exact-subject"
    assert member["role"] == "operator"
    assert set(member) == {
        "id",
        "user_id",
        "subject",
        "display_name",
        "role",
        "status",
        "user_status",
    }
    assert_hardened(created)
    roster = client.get("/api/team/members?limit=1&offset=1", headers=headers)
    assert roster.status_code == 200 and roster.json() == [member]
    assert_hardened(roster)
    updated = client.patch(
        f"/api/team/members/{member['id']}",
        headers=headers,
        json={"role": "viewer", "status": "disabled"},
    )
    assert updated.status_code == 200
    assert (updated.json()["role"], updated.json()["status"]) == ("viewer", "disabled")
    assert limiter.calls[-1][0].action.value == "request.mutation"
    assert limiter.calls[-1][1].value == str(actor_id)
    with database.SessionLocal() as session:
        events = list(
            session.scalars(
                select(SecurityAuditEvent).where(SecurityAuditEvent.action == "membership.change")
            )
        )
        assert len(events) == 2
        assert all(event.actor_membership_id == actor_id for event in events)


@pytest.mark.parametrize("role", ["operator", "viewer", "auditor"])
def test_nonadministrators_cannot_read_or_change_roster(team_http, role):
    client, _, database, _, _, actor_id, _, headers, _, _ = team_http
    with database.SessionLocal() as session:
        session.get(Membership, actor_id).role = role
        session.commit()
    for response in [client.get("/api/team/members", headers=headers), provision(client, headers)]:
        assert response.status_code == 403
        assert response.json() == {"detail": "Permission denied"}
        assert_hardened(response)


def test_admin_can_provision_but_cannot_transfer_ownership(team_http):
    client, _, database, _, _, actor_id, _, headers, _, _ = team_http
    with database.SessionLocal() as session:
        session.get(Membership, actor_id).role = "admin"
        session.commit()
    created = provision(client, headers)
    assert created.status_code == 201
    response = client.post(
        "/api/team/ownership", headers=headers, json={"membership_id": created.json()["id"]}
    )
    assert response.status_code == 403
    assert_hardened(response)


def test_transfer_invalidates_both_old_cookies_and_requires_new_login(team_http):
    client, _, database, _, _, actor_id, _, headers, _, _ = team_http
    member = provision(client, headers, role="admin").json()
    with database.SessionLocal() as session:
        issued = issue_browser_session(session, member["id"])
        session.commit()
    new_headers = {
        **headers,
        "Cookie": f"{SESSION_COOKIE_NAME}={issued.token}",
        CSRF_HEADER_NAME: issued.csrf_token,
    }
    response = client.post(
        "/api/team/ownership", headers=headers, json={"membership_id": member["id"]}
    )
    assert response.status_code == 200 and response.json()["role"] == "owner"
    assert_hardened(response)
    for old_cookie in [headers, new_headers]:
        assert client.get("/api/team/members", headers=old_cookie).status_code == 401
    with database.SessionLocal() as session:
        assert session.get(Membership, actor_id).role == "admin"
        issued = issue_browser_session(session, member["id"])
        session.commit()
    new_headers.update(
        {"Cookie": f"{SESSION_COOKIE_NAME}={issued.token}", CSRF_HEADER_NAME: issued.csrf_token}
    )
    assert client.get("/api/team/members", headers=new_headers).status_code == 200


@pytest.mark.parametrize(
    "fault",
    [
        "no_cookie",
        "bad_cookie",
        "duplicate_cookie",
        "no_origin",
        "wrong_origin",
        "no_csrf",
        "wrong_csrf",
        "duplicate_csrf",
    ],
)
def test_browser_proof_failures_never_provision(team_http, fault):
    client, _, database, limiter, _, _, issued, original, _, _ = team_http
    headers = dict(original)
    if fault == "no_cookie":
        headers.pop("Cookie")
    elif fault == "bad_cookie":
        headers["Cookie"] = f"{SESSION_COOKIE_NAME}={'X' * 43}"
    elif fault == "duplicate_cookie":
        headers["Cookie"] += f"; {SESSION_COOKIE_NAME}={issued.token}"
    elif fault == "no_origin":
        headers.pop("Origin")
    elif fault == "wrong_origin":
        headers["Origin"] = "https://attacker.example"
    elif fault == "no_csrf":
        headers.pop(CSRF_HEADER_NAME)
    elif fault == "wrong_csrf":
        headers[CSRF_HEADER_NAME] = "X" * 43
    else:
        headers = list(headers.items()) + [(CSRF_HEADER_NAME, issued.csrf_token)]
    response = provision(client, headers, subject="must-not-exist")
    assert response.status_code == 401
    assert_hardened(response)
    assert not limiter.calls
    with database.SessionLocal() as session:
        assert session.scalar(select(User).where(User.oidc_subject == "must-not-exist")) is None


@pytest.mark.parametrize("fault", ["absent_policy", "different_database", "wrong_issuer", "local"])
def test_capability_mismatch_cannot_fall_back(team_http, fault, monkeypatch):
    client, application, database, _, _, _, _, headers, _, _ = team_http
    original = getattr(application.state, WORKFLOW_REQUEST_BINDING_STATE)
    if fault == "absent_policy":
        monkeypatch.setattr(application.state, WORKFLOW_REQUEST_BINDING_STATE, None)
    elif fault == "different_database":
        clone = DatabaseRequestBinding("server", database.SessionLocal)
        setattr(
            application.state,
            WORKFLOW_REQUEST_BINDING_STATE,
            WorkflowRequestBinding(clone, original.policy),
        )
    elif fault == "wrong_issuer":
        setattr(
            application.state,
            WORKFLOW_REQUEST_BINDING_STATE,
            WorkflowRequestBinding(
                original.database, replace(original.policy, issuer="https://wrong.example")
            ),
        )
    else:
        local = DatabaseRequestBinding("local", database.SessionLocal)
        setattr(application.state, DATABASE_REQUEST_BINDING_STATE, local)
        setattr(
            application.state,
            WORKFLOW_REQUEST_BINDING_STATE,
            WorkflowRequestBinding(local, replace(original.policy, mode="local")),
        )
    response = provision(client, headers)
    assert response.status_code in {403, 503}
    assert_hardened(response)
    with database.SessionLocal() as session:
        assert session.scalar(select(User).where(User.oidc_subject == "exact-subject")) is None


@pytest.mark.parametrize(
    "payload",
    [
        {"subject": "secret-subject", "display_name": "Private", "role": "owner"},
        {
            "subject": "secret-subject",
            "display_name": "Private",
            "role": "viewer",
            "organization_id": 1,
        },
        {
            "subject": "secret-subject",
            "display_name": "Private",
            "role": "viewer",
            "issuer": "forged",
        },
        {"subject": "x" * 256, "display_name": "Private", "role": "viewer"},
    ],
)
def test_validation_does_not_echo_identity_inputs(team_http, payload):
    client, _, _, _, _, _, _, headers, _, _ = team_http
    response = client.post("/api/team/members", headers=headers, json=payload)
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid team request"}
    assert_hardened(response)


@pytest.mark.parametrize("query", ["limit=101", "limit=0", "offset=-1", "offset=1000001"])
def test_roster_window_is_bounded_at_http_boundary(team_http, query):
    client, _, _, _, _, _, _, headers, _, _ = team_http
    response = client.get(f"/api/team/members?{query}", headers=headers)
    assert response.status_code == 422
    assert_hardened(response)


def test_duplicate_and_unknown_targets_have_generic_conflicts(team_http):
    client, _, _, _, _, _, _, headers, _, _ = team_http
    assert provision(client, headers).status_code == 201
    responses = [
        provision(client, headers),
        client.patch(
            "/api/team/members/999999",
            headers=headers,
            json={"role": "viewer", "status": "disabled"},
        ),
    ]
    for response in responses:
        assert response.status_code == 409
        assert response.json() == {"detail": "Team change rejected"}
        assert_hardened(response)


def test_limiter_denial_and_failure_are_hardened(team_http):
    client, _, _, limiter, _, _, _, headers, _, _ = team_http
    limiter.decision = RateLimitDecision(allowed=False, retry_after_seconds=19)
    response = provision(client, headers)
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "19"
    assert_hardened(response)
    limiter.error = RateLimitUnavailable("private-database-detail")
    response = provision(client, headers)
    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication unavailable"}
    assert_hardened(response)


def test_audit_database_failure_rolls_back_and_hides_details(team_http, monkeypatch):
    client, _, database, _, _, _, _, headers, _, _ = team_http

    def fail(*args, **kwargs):
        raise OperationalError("private-sql", {}, Exception("private-password"))

    monkeypatch.setattr(team, "append_security_event", fail)
    response = provision(client, headers)
    assert response.status_code == 503
    assert response.json() == {"detail": "Team administration unavailable"}
    assert_hardened(response)
    with database.SessionLocal() as session:
        assert (
            session.scalar(
                select(func.count()).select_from(User).where(User.oidc_subject == "exact-subject")
            )
            == 0
        )


def test_role_revoked_after_cookie_admission_is_rechecked_by_core(team_http, monkeypatch):
    client, _, database, _, _, actor_id, _, headers, _, _ = team_http
    original = team.provision_member

    def after_admission(*args, **kwargs):
        with database.SessionLocal() as session:
            session.get(Membership, actor_id).role = "viewer"
            session.commit()
        return original(*args, **kwargs)

    monkeypatch.setattr(team, "provision_member", after_admission)
    response = provision(client, headers)
    assert response.status_code == 403
    assert_hardened(response)
