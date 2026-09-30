from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.authorization import AuthorizationContext, AuthorizationDenied, Role
from app.correlation import runner as correlation
from app.detection import runner as detection
from app.evidence import EvidenceStore
from app.models import (
    AssetRelationship,
    CorrelationRun,
    DetectionRun,
    Finding,
    FindingCorrelation,
    FrameworkMapping,
    Membership,
    Organization,
    ReportRun,
    SecurityAuditEvent,
    User,
)
from app.reporting import runner as reporting
from app.workflow_requests import WORKFLOW_REQUEST_BINDING_STATE
from tests.phase1 import Recorder
from tests.test_authenticated_requests import request_setup as request_setup
from tests.test_authentication import authentication_setup as authentication_setup
from tests.test_reporting import _prepared


@pytest.fixture(params=["detection", "correlation", "report"])
def stored(request, request_setup, environment):
    client, application, database, _, _, member_id, _, headers, own_id, other_id = request_setup
    with database.SessionLocal() as session:
        member = session.get(Membership, member_id)
        workflow = {
            "authorization": AuthorizationContext(
                member.organization_id, member.user_id, member.id, Role(member.role),
            ),
            "policy": getattr(application.state, WORKFLOW_REQUEST_BINDING_STATE).policy,
        }
        _prepared(Recorder(session, own_id), session, own_id, environment, workflow=workflow)
    kind = request.param
    runner, model, hook, start = {
        "detection": (detection, DetectionRun, "load_enrichment", detection.start_detection),
        "correlation": (
            correlation, CorrelationRun, "_finding_hashes", correlation.start_correlation,
        ),
        "report": (reporting, ReportRun, "_technical_markdown", reporting.start_report),
    }[kind]
    return SimpleNamespace(
        kind=kind, runner=runner, model=model, hook=hook, start=start, workflow=workflow,
        factory=database.SessionLocal, member_id=member_id, own_id=own_id, other_id=other_id,
        client=client, headers=headers, url=f"/api/dockyards/{own_id}/{kind}s",
    )


def snapshot(case):
    with case.factory() as session:
        findings = [
            (f.id, f.status, f.last_seen, f.last_detection_run_id, f.resolved_at)
            for f in session.scalars(select(Finding).order_by(Finding.id))
        ]
        related = [list(session.scalars(select(model.id).order_by(model.id)))
                   for model in (AssetRelationship, FindingCorrelation, FrameworkMapping)]
        return findings, related


def start(case):
    return case.client.post(case.url, headers=case.headers, json={})


@pytest.mark.parametrize("fault", ["role", "membership", "user", "issuer", "organization"])
def test_publication_rechecks_actor_and_rolls_back_results(stored, monkeypatch, fault):
    before = snapshot(stored)
    original = getattr(stored.runner, stored.hook)

    def change(*args, **kwargs):
        result = original(*args, **kwargs)
        with stored.factory() as session:
            member = session.get(Membership, stored.member_id)
            user = session.get(User, member.user_id)
            if fault == "role":
                member.role = "viewer"
            elif fault == "membership":
                member.status = "disabled"
            elif fault == "user":
                user.status = "disabled"
            elif fault == "issuer":
                user.oidc_issuer = "https://other.example"
            else:
                session.get(Organization, member.organization_id).slug = "different"
            session.commit()
        return result

    monkeypatch.setattr(stored.runner, stored.hook, change)
    response = start(stored)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "failed", body
    assert body["error"] == "Permission denied"
    assert body["evidence_path"] is None
    assert snapshot(stored) == before
    with stored.factory() as session:
        events = list(session.scalars(select(SecurityAuditEvent).where(
            SecurityAuditEvent.target_type == f"{stored.kind}_run",
            SecurityAuditEvent.target_id == str(body["id"]),
        )))
        assert [event.action for event in events] == [f"{stored.kind}.request"]


@pytest.mark.parametrize("fault", ["audit", "evidence"])
def test_publication_failure_keeps_previous_results_intact(stored, monkeypatch, fault):
    before = snapshot(stored)
    if fault == "audit":
        original = stored.runner.append_security_event

        def fail(*args, **kwargs):
            if kwargs["action"].value.endswith(".publish"):
                raise RuntimeError("audit unavailable")
            return original(*args, **kwargs)

        monkeypatch.setattr(stored.runner, "append_security_event", fail)
    else:
        def fail(*args, **kwargs):
            raise OSError("evidence unavailable")

        name = "write_export" if stored.kind == "report" else "write_metadata"
        monkeypatch.setattr(EvidenceStore, name, fail)
    response = start(stored)
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "failed"
    assert response.json()["evidence_path"] is None
    assert snapshot(stored) == before


def test_request_and_publication_retain_current_actor(stored, monkeypatch):
    original = getattr(stored.runner, stored.hook)

    def promote(*args, **kwargs):
        result = original(*args, **kwargs)
        with stored.factory() as session:
            session.get(Membership, stored.member_id).role = "owner"
            session.commit()
        return result

    monkeypatch.setattr(stored.runner, stored.hook, promote)
    response = start(stored)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "completed", body
    with stored.factory() as session:
        events = list(session.scalars(select(SecurityAuditEvent).where(
            SecurityAuditEvent.target_type == f"{stored.kind}_run",
            SecurityAuditEvent.target_id == str(body["id"]),
        ).order_by(SecurityAuditEvent.id)))
        assert [event.actor_role for event in events] == ["operator", "owner"]
        assert all(event.actor_membership_id == stored.member_id for event in events)


def test_direct_cross_tenant_start_is_denied(stored):
    with stored.factory() as session:
        with pytest.raises(AuthorizationDenied):
            stored.start(session, stored.other_id, **stored.workflow)


def test_request_audit_failure_cannot_leave_a_run(stored, monkeypatch):
    with stored.factory() as session:
        before = list(session.scalars(select(stored.model.id).order_by(stored.model.id)))

    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(stored.runner, "append_security_event", fail)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        start(stored)
    with stored.factory() as session:
        assert list(session.scalars(select(stored.model.id).order_by(stored.model.id))) == before


def test_results_remain_private_until_evidence_and_publication_commit(stored, monkeypatch):
    before = snapshot(stored)
    name = "write_export" if stored.kind == "report" else "write_metadata"
    original = getattr(EvidenceStore, name)
    observations = []

    def inspect(*args, **kwargs):
        assert snapshot(stored) == before
        with stored.factory() as session:
            pending = session.scalars(select(stored.model).order_by(stored.model.id.desc())).first()
            assert pending.status == "running"
            assert pending.evidence_path is None
        observations.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(EvidenceStore, name, inspect)
    response = start(stored)
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "completed", response.text
    assert observations
