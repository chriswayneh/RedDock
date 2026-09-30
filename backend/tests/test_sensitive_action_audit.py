import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app import api, findings, services
from app.authorization import AuthorizationContext, AuthorizationDenied, Role
from app.models import Dockyard, Finding, Membership, ScopeEntry, SecurityAuditEvent
from app.reporting import runner as reporting
from app.schemas import DockyardCreate
from app.workflow_requests import WORKFLOW_REQUEST_BINDING_STATE
from tests.phase1 import Recorder
from tests.test_authenticated_requests import request_setup as request_setup
from tests.test_authentication import authentication_setup as authentication_setup
from tests.test_reporting import _prepared


@pytest.fixture()
def sensitive(request_setup, environment):
    client, application, database, _, _, member_id, _, headers, own_id, other_id = request_setup
    with database.SessionLocal() as session:
        member = session.get(Membership, member_id)
        workflow = {
            "authorization": AuthorizationContext(
                member.organization_id,
                member.user_id,
                member.id,
                Role(member.role),
            ),
            "policy": getattr(application.state, WORKFLOW_REQUEST_BINDING_STATE).policy,
        }
        _prepared(Recorder(session, own_id), session, own_id, environment, workflow=workflow)
        finding_id = session.scalar(select(Finding.id).where(Finding.dockyard_id == own_id))
        scope = ScopeEntry(
            dockyard_id=own_id, rule="include", kind="hostname", value="host.example"
        )
        session.add(scope)
        session.commit()
        scope_id = scope.id
    return SimpleNamespace(
        client=client,
        factory=database.SessionLocal,
        member_id=member_id,
        headers=headers,
        own_id=own_id,
        other_id=other_id,
        workflow=workflow,
        finding_id=finding_id,
        scope_id=scope_id,
    )


def mutate(case, operation):
    prefix = f"/api/dockyards/{case.own_id}"
    if operation == "dockyard.create":
        return case.client.post(
            "/api/dockyards", headers=case.headers, json={"name": "Private workspace title"}
        )
    if operation == "scope.add":
        return case.client.post(
            prefix + "/scope",
            headers=case.headers,
            json={"rule": "include", "target": "127.0.0.2", "note": "Private scope note"},
        )
    if operation == "scope.remove":
        return case.client.delete(prefix + f"/scope/{case.scope_id}", headers=case.headers)
    return case.client.patch(
        prefix + f"/findings/{case.finding_id}",
        headers=case.headers,
        json={"status": "suppressed", "note": "Private finding note"},
    )


def state(case):
    with case.factory() as session:
        return (
            list(session.scalars(select(Dockyard.id).order_by(Dockyard.id))),
            list(session.scalars(select(ScopeEntry.id).order_by(ScopeEntry.id))),
            [(f.id, f.status, f.status_note) for f in session.scalars(select(Finding))],
        )


@pytest.mark.parametrize(
    "operation", ["dockyard.create", "scope.add", "scope.remove", "finding.update"]
)
def test_sensitive_mutations_record_actor_without_free_text(sensitive, operation):
    response = mutate(sensitive, operation)
    assert response.status_code in (200, 201, 204), response.text
    with sensitive.factory() as session:
        event = session.scalars(
            select(SecurityAuditEvent).where(
                SecurityAuditEvent.action == operation,
            )
        ).one()
        assert event.actor_membership_id == sensitive.member_id
        assert event.actor_role == "operator"
        serialized = json.dumps(
            {c.name: getattr(event, c.name) for c in event.__table__.columns}, default=str
        )
        assert "Private" not in serialized
        assert "127.0.0.2" not in serialized


@pytest.mark.parametrize(
    "operation", ["dockyard.create", "scope.add", "scope.remove", "finding.update"]
)
@pytest.mark.parametrize("fault", ["role", "audit"])
def test_sensitive_mutation_rechecks_authority_and_rolls_back_on_failure(
    sensitive,
    monkeypatch,
    operation,
    fault,
):
    before = state(sensitive)
    module = findings if operation == "finding.update" else services
    if fault == "audit":

        def fail(*args, **kwargs):
            raise RuntimeError("audit unavailable")

        monkeypatch.setattr(module, "append_security_event", fail)
        with pytest.raises(RuntimeError, match="audit unavailable"):
            mutate(sensitive, operation)
    else:
        name = (
            "current_workflow_actor" if operation == "dockyard.create" else "require_workflow_actor"
        )
        original = getattr(module, name)

        def downgrade(*args, **kwargs):
            with sensitive.factory() as session:
                session.get(Membership, sensitive.member_id).role = "viewer"
                session.commit()
            return original(*args, **kwargs)

        monkeypatch.setattr(module, name, downgrade)
        response = mutate(sensitive, operation)
        assert response.status_code == 403, response.text
    assert state(sensitive) == before
    with sensitive.factory() as session:
        assert (
            session.scalar(
                select(SecurityAuditEvent.id).where(
                    SecurityAuditEvent.action == operation,
                )
            )
            is None
        )


def test_workspace_creation_cannot_substitute_another_organization(sensitive):
    with sensitive.factory() as session:
        with pytest.raises(AuthorizationDenied):
            services.create_dockyard(
                session, 1, DockyardCreate(name="Denied"), **sensitive.workflow
            )


@pytest.mark.parametrize("audit_failure", [False, True])
def test_scope_resolution_requires_committed_admission(sensitive, monkeypatch, audit_failure):
    calls = []

    def resolve(host):
        with sensitive.factory() as session:
            event = session.scalars(
                select(SecurityAuditEvent).where(
                    SecurityAuditEvent.action == "scope.evaluate",
                )
            ).one()
            assert event.actor_membership_id == sensitive.member_id
        calls.append(host)
        return ("127.0.0.1",)

    monkeypatch.setattr(api, "system_resolver", resolve)
    if audit_failure:

        def fail(*args, **kwargs):
            raise RuntimeError("audit unavailable")

        monkeypatch.setattr(api, "append_security_event", fail)
        with pytest.raises(RuntimeError, match="audit unavailable"):
            sensitive.client.post(
                f"/api/dockyards/{sensitive.own_id}/scope/evaluate",
                headers=sensitive.headers,
                json={"target": "host.example", "resolve": True},
            )
        assert calls == []
    else:
        response = sensitive.client.post(
            f"/api/dockyards/{sensitive.own_id}/scope/evaluate",
            headers=sensitive.headers,
            json={"target": "host.example", "resolve": True},
        )
        assert response.status_code == 200, response.text
        assert calls == ["host.example"]


@pytest.fixture()
def export(sensitive):
    response = sensitive.client.post(
        f"/api/dockyards/{sensitive.own_id}/reports", headers=sensitive.headers, json={}
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "completed", response.text
    sensitive.report_id = response.json()["id"]
    return sensitive


@pytest.mark.parametrize("artifact", ["technical", "executive", "manifest", "dockpack"])
def test_auditor_exports_are_attributed(export, artifact):
    with export.factory() as session:
        session.get(Membership, export.member_id).role = "auditor"
        session.commit()
    response = export.client.get(
        f"/api/dockyards/{export.own_id}/reports/{export.report_id}/{artifact}",
        headers=export.headers,
    )
    assert response.status_code == 200, response.text
    with export.factory() as session:
        event = session.scalars(
            select(SecurityAuditEvent).where(
                SecurityAuditEvent.action == "report.export",
            )
        ).one()
        assert event.actor_role == "auditor"
        assert event.reason_code == f"{artifact}_export_admitted"
        assert event.actor_membership_id == export.member_id


@pytest.mark.parametrize("fault", ["role", "audit", "verification"])
@pytest.mark.parametrize("artifact", ["technical", "executive", "manifest", "dockpack"])
def test_export_failure_never_serves_an_artifact(export, monkeypatch, fault, artifact):
    original = reporting.artifact_path

    def verified_then_downgraded(*args):
        path = original(*args)
        with export.factory() as session:
            session.get(Membership, export.member_id).role = "viewer"
            session.commit()
        return path

    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    def invalid(*args, **kwargs):
        raise reporting.ReportRejected("artifact unavailable")

    if fault == "role":
        monkeypatch.setattr(reporting, "artifact_path", verified_then_downgraded)
    elif fault == "audit":
        monkeypatch.setattr(reporting, "append_security_event", fail)
    else:
        monkeypatch.setattr(reporting, "artifact_path", invalid)
    url = f"/api/dockyards/{export.own_id}/reports/{export.report_id}/{artifact}"
    if fault == "audit":
        with pytest.raises(RuntimeError, match="audit unavailable"):
            export.client.get(url, headers=export.headers)
    else:
        response = export.client.get(url, headers=export.headers)
        assert response.status_code == (403 if fault == "role" else 409), response.text
        assert response.headers["content-type"] == "application/json"
    with export.factory() as session:
        assert (
            session.scalar(
                select(SecurityAuditEvent.id).where(
                    SecurityAuditEvent.action == "report.export",
                )
            )
            is None
        )
