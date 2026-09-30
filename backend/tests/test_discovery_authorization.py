import pytest
from sqlalchemy import select

from app.discovery import registry, runner
from app.models import DiscoveryRun, Membership, Organization, ScopeEntry, SecurityAuditEvent, User
from tests.test_authenticated_requests import request_setup as request_setup
from tests.test_authentication import authentication_setup as authentication_setup
from tests.test_discovery import StubAdapter


@pytest.fixture()
def queued(request_setup, monkeypatch):
    client, _, database, _, _, membership_id, _, headers, own_id, other_id = request_setup
    adapter = StubAdapter()
    monkeypatch.setattr(registry, "get_adapter", lambda _: adapter)
    deliveries = []
    monkeypatch.setattr(runner, "submit_run", lambda *args: deliveries.append(args))
    with database.SessionLocal() as session:
        session.add(ScopeEntry(dockyard_id=own_id, rule="include", kind="ipv4", value="127.0.0.1"))
        session.commit()
    response = client.post(
        f"/api/dockyards/{own_id}/discoveries", headers=headers,
        json={"target": "127.0.0.1", "adapter": "stub", "profile": "safe"},
    )
    assert response.status_code == 202
    run_id, factory, runtime, receipt = deliveries.pop()
    assert factory is database.SessionLocal
    assert runtime.policy.mode == "server"
    return factory, membership_id, run_id, receipt, runtime.policy, adapter, other_id


def execute(queued):
    factory, _, run_id, receipt, policy, _, _ = queued
    runner.execute_run(run_id, factory, receipt, policy)


@pytest.mark.parametrize("fault", [
    "membership", "user", "role", "issuer", "organization", "missing_receipt",
    "wrong_run", "wrong_tenant", "denied_receipt",
])
def test_queued_authority_is_rechecked_before_contact(queued, fault, monkeypatch):
    factory, membership_id, run_id, receipt, _, adapter, _ = queued
    with factory() as session:
        membership = session.get(Membership, membership_id)
        user = session.get(User, membership.user_id)
        event = session.get(SecurityAuditEvent, receipt)
        if fault == "membership":
            membership.status = "disabled"
        elif fault == "user":
            user.status = "disabled"
        elif fault == "role":
            membership.role = "viewer"
        elif fault == "issuer":
            user.oidc_issuer = "https://other.example"
        elif fault == "organization":
            session.get(Organization, membership.organization_id).slug = "other"
        elif fault == "missing_receipt":
            session.delete(event)
        elif fault == "wrong_run":
            event.target_id = "999999"
        elif fault == "wrong_tenant":
            event.organization_id = 1
        else:
            event.outcome = "denied"
        session.commit()
    monkeypatch.setattr(runner, "evaluate", lambda *a, **k: pytest.fail("Reached scope resolver"))
    execute(queued)
    assert not adapter.requests
    with factory() as session:
        assert session.get(DiscoveryRun, run_id).status == "denied"
        event = session.scalar(select(SecurityAuditEvent).where(
            SecurityAuditEvent.action == "discovery.execute",
        ))
        assert event.outcome == "denied"
        assert event.actor_user_id is None


def test_final_authority_check_catches_revocation_during_scope_resolution(queued, monkeypatch):
    factory, membership_id, run_id, _, _, adapter, _ = queued
    original = runner.evaluate

    def revoke(*args, **kwargs):
        with factory() as session:
            session.get(Membership, membership_id).role = "viewer"
            session.commit()
        return original(*args, **kwargs)

    monkeypatch.setattr(runner, "evaluate", revoke)
    execute(queued)
    assert not adapter.requests
    with factory() as session:
        assert session.get(DiscoveryRun, run_id).status == "denied"


def test_execution_uses_current_role_and_duplicate_delivery_does_not_repeat(queued):
    factory, membership_id, run_id, receipt, _, adapter, _ = queued
    with factory() as session:
        session.get(Membership, membership_id).role = "owner"
        session.commit()
    execute(queued)
    execute(queued)
    assert len(adapter.requests) == 1
    with factory() as session:
        assert session.get(DiscoveryRun, run_id).status == "completed"
        request = session.get(SecurityAuditEvent, receipt)
        event = session.scalars(select(SecurityAuditEvent).where(
            SecurityAuditEvent.action == "discovery.execute",
        )).one()
        assert request.actor_role == "operator"
        assert event.actor_role == "owner"
        assert event.actor_membership_id == membership_id
        assert event.organization_id == request.organization_id


def test_execution_audit_failure_prevents_adapter_contact(queued, monkeypatch):
    factory, _, run_id, _, _, adapter, _ = queued

    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(runner, "append_security_event", fail)
    execute(queued)
    assert not adapter.requests
    with factory() as session:
        assert session.get(DiscoveryRun, run_id).status == "failed"
        assert session.scalar(select(SecurityAuditEvent.id).where(
            SecurityAuditEvent.action == "discovery.execute",
        )) is None


def test_admission_audit_failure_rolls_back_run(request_setup, monkeypatch):
    client, _, database, _, _, _, _, headers, own_id, _ = request_setup
    monkeypatch.setattr(registry, "get_adapter", lambda _: StubAdapter())
    with database.SessionLocal() as session:
        session.add(ScopeEntry(dockyard_id=own_id, rule="include", kind="ipv4", value="127.0.0.1"))
        session.commit()

    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(runner, "append_security_event", fail)
    monkeypatch.setattr(runner, "submit_run", lambda *a: pytest.fail("Queued unaudited work"))
    with pytest.raises(RuntimeError, match="audit unavailable"):
        client.post(
            f"/api/dockyards/{own_id}/discoveries", headers=headers,
            json={"target": "127.0.0.1", "adapter": "stub", "profile": "safe"},
        )
    with database.SessionLocal() as session:
        assert session.scalar(select(DiscoveryRun.id)) is None
