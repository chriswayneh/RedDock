import pytest
from sqlalchemy import select

from app import lab
from app.config import get_settings
from app.lab_capabilities import EXTENDED_SERVICE_DISCOVERY
from app.models import LabAuditEvent, LabAuthorization, Membership, SecurityAuditEvent, User
from tests.test_authenticated_requests import request_setup as request_setup
from tests.test_authentication import authentication_setup as authentication_setup
from tests.test_lab import _enable_lab


def grant(case):
    client, _, _, _, _, _, _, headers, own_id, _ = case
    return client.post(f"/api/dockyards/{own_id}/lab/authorizations", headers=headers, json={
        "capability": EXTENDED_SERVICE_DISCOVERY, "acknowledgement": lab.LAB_ACKNOWLEDGEMENT,
        "note": "Approved isolated lab operation", "duration_minutes": 30,
    })


def revoke(case, grant_id):
    client, _, _, _, _, _, _, headers, own_id, _ = case
    return client.post(f"/api/dockyards/{own_id}/lab/authorizations/{grant_id}/revoke",
                       headers=headers, json={})


def test_grant_and_revoke_record_the_current_actor(request_setup, monkeypatch):
    _enable_lab(monkeypatch)
    _, _, database, _, _, member_id, _, _, _, _ = request_setup
    first = grant(request_setup)
    assert first.status_code == 201, first.text
    with database.SessionLocal() as session:
        session.get(Membership, member_id).role = "owner"
        session.commit()
    assert revoke(request_setup, first.json()["id"]).status_code == 200
    with database.SessionLocal() as session:
        events = list(session.scalars(select(SecurityAuditEvent).where(
            SecurityAuditEvent.action.in_(["lab.authorize", "lab.revoke"]),
        ).order_by(SecurityAuditEvent.id)))
        assert [event.actor_role for event in events] == ["operator", "owner"]
        assert all(event.actor_membership_id == member_id for event in events)
        assert all(event.target_id == str(first.json()["id"]) for event in events)
        assert all(event.outcome == "success" for event in events)


@pytest.mark.parametrize("operation", ["grant", "revoke"])
@pytest.mark.parametrize("fault", ["role", "membership", "user", "issuer"])
def test_current_authority_is_rechecked_after_request_authentication(
    request_setup, monkeypatch, operation, fault,
):
    _enable_lab(monkeypatch)
    first = grant(request_setup)
    assert first.status_code == 201, first.text
    _, _, database, _, _, member_id, _, _, _, _ = request_setup
    original = lab.require_workflow_actor

    def change_then_recheck(*args):
        with database.SessionLocal() as session:
            member = session.get(Membership, member_id)
            user = session.get(User, member.user_id)
            if fault == "role":
                member.role = "viewer"
            elif fault == "membership":
                member.status = "disabled"
            elif fault == "user":
                user.status = "disabled"
            else:
                user.oidc_issuer = "https://different.example"
            session.commit()
        return original(*args)

    monkeypatch.setattr(lab, "require_workflow_actor", change_then_recheck)
    response = grant(request_setup) if operation == "grant" else revoke(
        request_setup, first.json()["id"],
    )
    assert response.status_code == 403, response.text
    assert response.json() == {"detail": "Permission denied"}
    with database.SessionLocal() as session:
        grants = list(session.scalars(select(LabAuthorization)))
        assert len(grants) == 1
        assert grants[0].status == "active"
        assert len(list(session.scalars(select(LabAuditEvent)))) == 1


@pytest.mark.parametrize("operation", ["grant", "revoke"])
def test_security_audit_failure_rolls_back_lab_mutation(request_setup, monkeypatch, operation):
    _enable_lab(monkeypatch)
    first = grant(request_setup)
    assert first.status_code == 201, first.text

    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(lab, "append_security_event", fail)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        if operation == "grant":
            grant(request_setup)
        else:
            revoke(request_setup, first.json()["id"])
    database = request_setup[2]
    with database.SessionLocal() as session:
        grants = list(session.scalars(select(LabAuthorization)))
        assert len(grants) == 1
        assert grants[0].status == "active"
        assert grants[0].revoked_at is None
        assert len(list(session.scalars(select(LabAuditEvent)))) == 1
        assert len(list(session.scalars(select(SecurityAuditEvent).where(
            SecurityAuditEvent.action.in_(["lab.authorize", "lab.revoke"]),
        )))) == 1


def test_disabled_lab_policy_is_attributed_without_granting_access(request_setup, monkeypatch):
    monkeypatch.setenv("REDDOCK_LAB_MODE_ENABLED", "false")
    get_settings.cache_clear()
    response = grant(request_setup)
    assert response.status_code == 403, response.text
    with request_setup[2].SessionLocal() as session:
        event = session.scalars(select(SecurityAuditEvent).where(
            SecurityAuditEvent.action == "lab.authorize",
        )).one()
        assert event.outcome == "denied"
        assert event.reason_code == "deployment_disabled"
        assert event.actor_membership_id == request_setup[5]
        assert session.scalars(select(LabAuthorization)).one().status == "denied"
