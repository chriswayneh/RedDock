from dataclasses import replace
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.browser_security import CSRF_HEADER_NAME, SESSION_COOKIE_NAME
from app.database import DatabaseRequestBinding
from app.intelligence import runner as intelligence
from app.models import (
    Finding,
    IntelligenceRun,
    Membership,
    Organization,
    ScopeEntry,
    SecurityAuditEvent,
    User,
    ValidationRun,
)
from app.session_auth import issue_browser_session
from app.validation import runner as validation
from app.workflow_requests import WORKFLOW_REQUEST_BINDING_STATE
from tests.phase1 import Recorder
from tests.test_authenticated_requests import request_setup as request_setup
from tests.test_authentication import authentication_setup as authentication_setup
from tests.test_intelligence import FakeProvider, _prepared


@pytest.fixture(params=["validation", "intelligence"])
def approval(request, request_setup, monkeypatch):
    client, application, database, _, _, membership_id, _, headers, own_id, other_id = request_setup
    provider = FakeProvider()
    monkeypatch.setattr(intelligence, "get_provider", lambda: provider)
    probes = []

    def probe(*args):
        probes.append(args)
        return validation.ValidationResult("confirmed", "high", "Confirmed", {}, b"{}")

    monkeypatch.setattr(validation, "_validate", probe)
    with database.SessionLocal() as session:
        _prepared(Recorder(session, own_id), session, own_id)
        session.add(ScopeEntry(
            dockyard_id=own_id, rule="include", kind="url", value="http://127.0.0.1:8080",
        ))
        session.commit()
        finding_id = session.scalar(select(Finding.id).where(
            Finding.dockyard_id == own_id, Finding.rule_id == "plaintext-http",
        ))
    kind = request.param
    create_url = (f"/api/dockyards/{own_id}/findings/{finding_id}/validations"
                  if kind == "validation" else f"/api/dockyards/{own_id}/intelligence")
    response = client.post(create_url, headers=headers, json={})
    assert response.status_code == 201, response.text
    run_id = response.json()["id"]
    path = "validations" if kind == "validation" else "intelligence"
    return SimpleNamespace(
        client=client, application=application, factory=database.SessionLocal,
        membership_id=membership_id, headers=headers, own_id=own_id, other_id=other_id,
        kind=kind, create_url=create_url, run_id=run_id,
        url=f"/api/dockyards/{own_id}/{path}/{run_id}/approve",
        runner=validation if kind == "validation" else intelligence,
        model=ValidationRun if kind == "validation" else IntelligenceRun,
        calls=probes if kind == "validation" else provider.calls,
    )


def approve(case, headers=None):
    return case.client.post(case.url, headers=headers or case.headers,
                            json={"note": "Reviewed and approved the retained request."})


def after_verification(case, monkeypatch, change):
    name = "_evaluate" if case.kind == "validation" else "_verify_retained_packet"
    original = getattr(case.runner, name)

    def verify(*args):
        result = original(*args)
        with case.factory() as session:
            change(session)
            session.commit()
        return result

    monkeypatch.setattr(case.runner, name, verify)


@pytest.mark.parametrize("fault", ["membership", "user", "role", "issuer", "organization"])
def test_final_approval_rechecks_identity_after_verification(approval, monkeypatch, fault):
    def revoke(session):
        member = session.get(Membership, approval.membership_id)
        user = session.get(User, member.user_id)
        if fault == "membership":
            member.status = "disabled"
        elif fault == "user":
            user.status = "disabled"
        elif fault == "role":
            member.role = "viewer"
        elif fault == "issuer":
            user.oidc_issuer = "https://other.example"
        else:
            session.get(Organization, member.organization_id).slug = "changed"

    after_verification(approval, monkeypatch, revoke)
    response = approve(approval)
    assert response.status_code == 403, response.text
    assert response.json() == {"detail": "Permission denied"}
    assert not approval.calls
    with approval.factory() as session:
        run = session.get(approval.model, approval.run_id)
        assert run.status == "pending_approval"
        assert run.approval_note is None
        assert session.scalar(select(SecurityAuditEvent.id).where(
            SecurityAuditEvent.action == f"{approval.kind}.approve",
        )) is None


def test_approval_records_current_role_and_cannot_be_repeated(approval, monkeypatch):
    after_verification(approval, monkeypatch, lambda s:
                       setattr(s.get(Membership, approval.membership_id), "role", "owner"))
    response = approve(approval)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "completed"
    assert approve(approval).status_code == 409
    assert len(approval.calls) == 1
    with approval.factory() as session:
        requested = session.scalars(select(SecurityAuditEvent).where(
            SecurityAuditEvent.action == f"{approval.kind}.request",
        )).one()
        approved = session.scalars(select(SecurityAuditEvent).where(
            SecurityAuditEvent.action == f"{approval.kind}.approve",
        )).one()
        assert requested.actor_role == "operator"
        assert approved.actor_role == "owner"
        assert approved.actor_membership_id == approval.membership_id
        assert approved.organization_id == requested.organization_id
        assert approved.target_id == str(approval.run_id)


def test_another_current_member_can_approve_a_revoked_requesters_packet(approval):
    with approval.factory() as session:
        requester = session.get(Membership, approval.membership_id)
        requester.status = "disabled"
        user = User(
            oidc_issuer=session.get(User, requester.user_id).oidc_issuer,
            oidc_subject="second-approver", display_name="Second Approver", status="active",
        )
        session.add(user)
        session.flush()
        approver = Membership(organization_id=requester.organization_id, user_id=user.id,
                              role="operator", status="active")
        session.add(approver)
        session.flush()
        proof = issue_browser_session(session, approver.id)
        approver_id = approver.id
        session.commit()
    headers = dict(approval.headers)
    headers["Cookie"] = f"{SESSION_COOKIE_NAME}={proof.token}"
    headers[CSRF_HEADER_NAME] = proof.csrf_token
    response = approve(approval, headers)
    assert response.status_code == 200, response.text
    assert len(approval.calls) == 1
    with approval.factory() as session:
        event = session.scalars(select(SecurityAuditEvent).where(
            SecurityAuditEvent.action == f"{approval.kind}.approve",
        )).one()
        assert event.actor_membership_id == approver_id


def test_approval_audit_failure_rolls_back_claim_before_contact(approval, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(approval.runner, "append_security_event", fail)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        approve(approval)
    assert not approval.calls
    with approval.factory() as session:
        run = session.get(approval.model, approval.run_id)
        assert run.status == "pending_approval"
        assert run.approved_at is None


@pytest.mark.parametrize("fault", ["missing", "database", "mode"])
def test_workflow_policy_must_match_exact_request_binding(approval, fault):
    state = approval.application.state
    binding = getattr(state, WORKFLOW_REQUEST_BINDING_STATE)
    if fault == "missing":
        delattr(state, WORKFLOW_REQUEST_BINDING_STATE)
    elif fault == "database":
        setattr(state, WORKFLOW_REQUEST_BINDING_STATE, replace(
            binding, database=DatabaseRequestBinding("server", binding.database.session_factory),
        ))
    else:
        setattr(state, WORKFLOW_REQUEST_BINDING_STATE, replace(
            binding, policy=replace(binding.policy, mode="local"),
        ))
    try:
        response = approve(approval)
        assert response.status_code == 503
        assert not approval.calls
    finally:
        setattr(state, WORKFLOW_REQUEST_BINDING_STATE, binding)


@pytest.mark.parametrize("fault", ["role", "audit"])
def test_request_creation_rolls_back_if_final_authority_or_audit_fails(
    approval, monkeypatch, fault,
):
    with approval.factory() as session:
        session.get(approval.model, approval.run_id).status = "completed"
        session.commit()
    if fault == "audit":
        def fail(*args, **kwargs):
            raise RuntimeError("audit unavailable")

        monkeypatch.setattr(approval.runner, "append_security_event", fail)
        with pytest.raises(RuntimeError, match="audit unavailable"):
            approval.client.post(approval.create_url, headers=approval.headers, json={})
    else:
        name = "_evaluate" if approval.kind == "validation" else "_packet"
        original = getattr(approval.runner, name)

        def downgrade(*args):
            result = original(*args)
            with approval.factory() as session:
                session.get(Membership, approval.membership_id).role = "viewer"
                session.commit()
            return result

        monkeypatch.setattr(approval.runner, name, downgrade)
        response = approval.client.post(approval.create_url, headers=approval.headers, json={})
        assert response.status_code == 403, response.text
    assert not approval.calls
    with approval.factory() as session:
        assert list(session.scalars(select(approval.model.id))) == [approval.run_id]
        assert len(list(session.scalars(select(SecurityAuditEvent.id).where(
            SecurityAuditEvent.action == f"{approval.kind}.request",
        )))) == 1
