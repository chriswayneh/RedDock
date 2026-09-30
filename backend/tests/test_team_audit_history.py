from datetime import datetime

import pytest
from sqlalchemy import func, select

from app import team_administration as team
from app.models import Membership, SecurityAuditEvent
from app.security_audit import SecurityAction, SecurityOutcome, append_security_event
from tests.test_authenticated_requests import request_setup as request_setup
from tests.test_authentication import authentication_setup as authentication_setup
from tests.test_team_administration_http import assert_hardened
from tests.test_team_administration_http import team_http as team_http


def seed_history(database, membership_id, count=4):
    with database.SessionLocal() as session:
        organization_id = session.get(Membership, membership_id).organization_id
        ids = []
        for index in range(count):
            event = append_security_event(
                session,
                organization_id=organization_id,
                action=SecurityAction.AUTHENTICATION_DENY,
                outcome=SecurityOutcome.DENIED,
                reason_code=f"test_denial_{index}",
            )
            ids.append(event.id)
            append_security_event(
                session,
                organization_id=1,
                action=SecurityAction.AUTHENTICATION_DENY,
                outcome=SecurityOutcome.DENIED,
                reason_code="other_organization",
            )
        session.commit()
    return ids


@pytest.mark.parametrize("role", ["owner", "admin", "auditor"])
def test_audit_read_is_bounded_scoped_and_excludes_identity_fields(team_http, role):
    client, _, database, limiter, _, actor_id, _, headers, _, _ = team_http
    ids = seed_history(database, actor_id)
    with database.SessionLocal() as session:
        session.get(Membership, actor_id).role = role
        session.commit()
        count = session.scalar(select(func.count()).select_from(SecurityAuditEvent))
    response = client.get("/api/team/audit?limit=2", headers=headers)
    assert response.status_code == 200
    assert_hardened(response)
    body = response.json()
    assert set(body) == {"items", "next_before_id"}
    assert [item["id"] for item in body["items"]] == ids[-2:][::-1]
    assert body["next_before_id"] == ids[-2]
    assert set(body["items"][0]) == {
        "id",
        "actor_user_id",
        "actor_membership_id",
        "actor_role",
        "action",
        "outcome",
        "target_type",
        "target_id",
        "reason_code",
        "request_id",
        "created_at",
    }
    assert datetime.fromisoformat(body["items"][0]["created_at"]).tzinfo is not None
    assert "other_organization" not in response.text
    assert "provisioned-subject" not in response.text
    assert not limiter.calls  # A bounded audit read does not spend the mutation budget.
    with database.SessionLocal() as session:
        assert session.scalar(select(func.count()).select_from(SecurityAuditEvent)) == count


def test_cursor_does_not_repeat_rows_when_new_events_arrive(team_http):
    client, _, database, _, _, actor_id, _, headers, _, _ = team_http
    ids = seed_history(database, actor_id)
    first = client.get("/api/team/audit?limit=2", headers=headers).json()
    seed_history(database, actor_id, count=1)
    second = client.get(
        f"/api/team/audit?limit=2&before_id={first['next_before_id']}", headers=headers
    ).json()
    assert [row["id"] for row in second["items"]] == ids[:2][::-1]
    third = client.get(
        f"/api/team/audit?limit=2&before_id={second['next_before_id']}", headers=headers
    ).json()
    assert len(third["items"]) == 1  # Original browser-session issuance remains in history.
    assert third["next_before_id"] is None
    empty = client.get("/api/team/audit?before_id=1", headers=headers).json()
    assert empty == {"items": [], "next_before_id": None}


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_audit_read_requires_audit_permission(team_http, role):
    client, _, database, _, _, actor_id, _, headers, _, _ = team_http
    with database.SessionLocal() as session:
        session.get(Membership, actor_id).role = role
        session.commit()
    response = client.get("/api/team/audit", headers=headers)
    assert response.status_code == 403
    assert_hardened(response)


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=101",
        "before_id=0",
        "before_id=-1",
        "before_id=true",
        "before_id=9223372036854775808",
    ],
)
def test_audit_query_bounds_do_not_expose_validation_input(team_http, query):
    client, _, _, _, _, _, _, headers, _, _ = team_http
    response = client.get(f"/api/team/audit?{query}", headers=headers)
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid team request"}
    assert_hardened(response)


def test_auditor_cannot_use_audit_access_to_read_roster_or_provision(team_http):
    client, _, database, _, _, actor_id, _, headers, _, _ = team_http
    with database.SessionLocal() as session:
        session.get(Membership, actor_id).role = "auditor"
        session.commit()
    assert client.get("/api/team/audit", headers=headers).status_code == 200
    assert client.get("/api/team/members", headers=headers).status_code == 403
    assert (
        client.post(
            "/api/team/members",
            headers=headers,
            json={
                "subject": "new-subject",
                "display_name": "New",
                "role": "viewer",
            },
        ).status_code
        == 403
    )


@pytest.mark.parametrize("change", ["role", "disabled"])
def test_audit_rechecks_permission_after_browser_admission(team_http, monkeypatch, change):
    client, _, database, _, _, actor_id, _, headers, _, _ = team_http
    original = team.audit_history

    def revoked(*args, **kwargs):
        with database.SessionLocal() as session:
            member = session.get(Membership, actor_id)
            if change == "role":
                member.role = "viewer"
            else:
                member.status = "disabled"
            session.commit()
        return original(*args, **kwargs)

    monkeypatch.setattr(team, "audit_history", revoked)
    response = client.get("/api/team/audit", headers=headers)
    assert response.status_code == 403
    assert_hardened(response)


def test_audit_preserves_retained_actor_snapshot_after_identity_is_unlinked(team_http):
    client, _, database, _, _, _, _, headers, _, _ = team_http
    with database.SessionLocal() as session:
        event = session.scalar(select(SecurityAuditEvent))
        event.actor_user_id = None
        event.actor_membership_id = None
        session.commit()
    body = client.get("/api/team/audit", headers=headers).json()
    assert body["items"][0]["actor_user_id"] is None
    assert body["items"][0]["actor_membership_id"] is None
    assert body["items"][0]["actor_role"] == "operator"  # Issued before fixture promotion.
