from dataclasses import replace

import pytest
from sqlalchemy import func, select

from app import team_administration as team
from app.authorization import LOCAL_AUTHORIZATION, AuthorizationContext, AuthorizationDenied, Role
from app.models import BrowserSession, Membership, Organization, SecurityAuditEvent, User
from app.session_auth import issue_browser_session, resolve_browser_session
from app.workflow_authorization import LOCAL_WORKFLOW_POLICY, workflow_execution_policy
from tests.test_authentication import authentication_setup as authentication_setup


@pytest.fixture()
def administration(authentication_setup):
    database, config, _, _, _, membership_id = authentication_setup
    with database.SessionLocal() as session:
        member = session.get(Membership, membership_id)
        member.role = "owner"
        actor = AuthorizationContext(member.organization_id, member.user_id, member.id, Role.OWNER)
        session.commit()
    return database, {"authorization": actor, "policy": workflow_execution_policy(config)}


def provision(database, workflow, subject="new-member", role="operator"):
    with database.SessionLocal() as session:
        return team.provision_member(
            session, subject=subject, display_name="Team Member", role=role, **workflow
        )


def events(database):
    with database.SessionLocal() as session:
        return list(session.scalars(select(SecurityAuditEvent).order_by(SecurityAuditEvent.id)))


def test_provision_exact_identity_and_paginate_roster(administration):
    database, workflow = administration
    member = provision(database, workflow)
    assert (member.subject, member.role, member.status) == ("new-member", Role.OPERATOR, "active")
    with database.SessionLocal() as session:
        roster = team.list_members(session, limit=1, offset=1, **workflow)
        assert roster == [member]
        assert not session.in_transaction()
    event = events(database)[0]
    assert (event.action, event.reason_code, event.target_id) == (
        "membership.change",
        "provisioned_operator",
        str(member.id),
    )
    assert event.actor_membership_id == workflow["authorization"].membership_id
    assert event.actor_role == "owner"


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject", ""),
        ("subject", " trailing "),
        ("subject", "a\nb"),
        ("subject", "x" * 256),
        ("subject", None),
        ("display_name", "x" * 121),
        ("display_name", "bad\x7f"),
        ("role", "owner"),
        ("role", "unknown"),
        ("role", None),
    ],
)
def test_invalid_provision_is_side_effect_free(administration, field, value):
    database, workflow = administration
    arguments = dict(subject="new", display_name="New", role="operator")
    arguments[field] = value
    with database.SessionLocal() as session, pytest.raises(team.TeamAdministrationRejected):
        team.provision_member(session, **arguments, **workflow)
    assert events(database) == []


@pytest.mark.parametrize("role", ["operator", "auditor", "viewer"])
def test_stale_owner_context_cannot_manage_members(administration, role):
    database, workflow = administration
    with database.SessionLocal() as session:
        session.get(Membership, workflow["authorization"].membership_id).role = role
        session.commit()
    with pytest.raises(AuthorizationDenied):
        provision(database, workflow)
    assert events(database) == []


@pytest.mark.parametrize(
    "change",
    ["member_disabled", "user_disabled", "wrong_issuer", "wrong_org", "local", "insecure_issuer"],
)
def test_administration_requires_current_configured_identity(administration, change):
    database, workflow = administration
    if change in {"member_disabled", "user_disabled"}:
        with database.SessionLocal() as session:
            actor = workflow["authorization"]
            record = (
                session.get(Membership, actor.membership_id)
                if change == "member_disabled"
                else session.get(User, actor.user_id)
            )
            record.status = "disabled"
            session.commit()
    elif change == "local":
        workflow = {"authorization": LOCAL_AUTHORIZATION, "policy": LOCAL_WORKFLOW_POLICY}
    else:
        replacements = {
            "wrong_issuer": {"issuer": "https://other.example"},
            "wrong_org": {"organization_slug": "other"},
            "insecure_issuer": {"issuer": "http://identity.example"},
        }
        workflow = {**workflow, "policy": replace(workflow["policy"], **replacements[change])}
    with database.SessionLocal() as session, pytest.raises(AuthorizationDenied):
        team.list_members(session, **workflow)


def test_duplicate_or_existing_unlinked_identity_is_not_attached(administration):
    database, workflow = administration
    provision(database, workflow)
    with pytest.raises(team.TeamAdministrationRejected, match="already provisioned"):
        provision(database, workflow)
    with database.SessionLocal() as session:
        session.add(
            User(
                oidc_issuer=workflow["policy"].issuer,
                oidc_subject="orphan",
                display_name="Existing",
                status="active",
            )
        )
        session.commit()
    with pytest.raises(team.TeamAdministrationRejected, match="already provisioned"):
        provision(database, workflow, "orphan")
    assert len(events(database)) == 1


def test_member_cap_counts_disabled_members(administration, monkeypatch):
    database, workflow = administration
    member = provision(database, workflow)
    with database.SessionLocal() as session:
        session.get(Membership, member.id).status = "disabled"
        session.commit()
    monkeypatch.setattr(team, "MAX_TEAM_MEMBERS", 2)
    with pytest.raises(team.TeamAdministrationRejected, match="limit"):
        provision(database, workflow, "overflow")


@pytest.mark.parametrize("role,status", [("viewer", "active"), ("operator", "disabled")])
def test_access_change_revokes_all_sessions_with_atomic_audit(administration, role, status):
    database, workflow = administration
    member = provision(database, workflow)
    with database.SessionLocal() as session:
        tokens = [issue_browser_session(session, member.id) for _ in range(2)]
        session.commit()
    with database.SessionLocal() as session:
        result = team.change_member(session, member.id, role=role, status=status, **workflow)
        assert (result.role, result.status) == (role, status)
    with database.SessionLocal() as session:
        assert all(resolve_browser_session(session, token.token) is None for token in tokens)
        assert all(row.revoked_at for row in session.scalars(select(BrowserSession)))
    assert [(event.action, event.actor_role) for event in events(database)[-2:]] == [
        ("membership.sessions_revoke", "owner"),
        ("membership.change", "owner"),
    ]


def test_no_op_preserves_sessions_and_does_not_add_audit(administration):
    database, workflow = administration
    member = provision(database, workflow)
    with database.SessionLocal() as session:
        token = issue_browser_session(session, member.id)
        session.commit()
    with database.SessionLocal() as session:
        team.change_member(session, member.id, role="operator", status="active", **workflow)
    with database.SessionLocal() as session:
        assert resolve_browser_session(session, token.token)
    assert [event.action for event in events(database)] == ["membership.change", "session.issue"]


@pytest.mark.parametrize("operation", ["provision", "change", "transfer"])
def test_audit_failure_rolls_back_identity_and_session_changes(
    administration, monkeypatch, operation
):
    database, workflow = administration
    member = provision(database, workflow)
    with database.SessionLocal() as session:
        tokens = [
            issue_browser_session(session, item)
            for item in (member.id, workflow["authorization"].membership_id)
        ]
        session.commit()
    real_append = team.append_security_event
    calls = []

    def fail_late(*args, **kwargs):
        event = real_append(*args, **kwargs)
        calls.append(event)
        if operation != "transfer" or len(calls) == 4:
            raise RuntimeError("audit unavailable")
        return event

    monkeypatch.setattr(team, "append_security_event", fail_late)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        if operation == "provision":
            provision(database, workflow, "rolled-back")
        else:
            with database.SessionLocal() as session:
                if operation == "change":
                    team.change_member(
                        session, member.id, role="viewer", status="disabled", **workflow
                    )
                else:
                    team.transfer_ownership(session, member.id, **workflow)
    with database.SessionLocal() as session:
        assert session.get(Membership, member.id).role == "operator"
        assert session.get(Membership, member.id).status == "active"
        assert session.get(Membership, workflow["authorization"].membership_id).role == "owner"
        assert all(resolve_browser_session(session, token.token) for token in tokens)
        assert (
            session.scalar(
                select(func.count()).select_from(User).where(User.oidc_subject == "rolled-back")
            )
            == 0
        )
    assert [event.action for event in events(database)] == [
        "membership.change", "session.issue", "session.issue",
    ]


def test_transfer_moves_ownership_and_revokes_both_members_sessions(administration):
    database, workflow = administration
    member = provision(database, workflow, role="viewer")
    original = workflow["authorization"]
    with database.SessionLocal() as session:
        tokens = [
            issue_browser_session(session, item) for item in (member.id, original.membership_id)
        ]
        session.commit()
    with database.SessionLocal() as session:
        assert team.transfer_ownership(session, member.id, **workflow).role == "owner"
    with database.SessionLocal() as session:
        assert session.get(Membership, original.membership_id).role == "admin"
        assert all(resolve_browser_session(session, token.token) is None for token in tokens)
    assert [event.reason_code for event in events(database)[-4:]] == [
        "access_changed",
        "access_changed",
        "ownership_relinquished",
        "ownership_received",
    ]
    assert all(event.actor_role == "owner" for event in events(database)[-4:])
    with database.SessionLocal() as session, pytest.raises(AuthorizationDenied):
        team.transfer_ownership(session, original.membership_id, **workflow)
    # The former owner retains ordinary administration rights after signing in again.
    assert provision(database, workflow, "by-admin").role == "operator"


@pytest.mark.parametrize(
    "invalid",
    ["self", "disabled_member", "disabled_user", "local", "missing", "cross_org", "second_owner"],
)
def test_transfer_refuses_invalid_recipient_or_ownership(administration, invalid):
    database, workflow = administration
    member = provision(database, workflow)
    recipient = member.id
    with database.SessionLocal() as session:
        if invalid == "self":
            recipient = workflow["authorization"].membership_id
        elif invalid == "disabled_member":
            session.get(Membership, member.id).status = "disabled"
        elif invalid == "disabled_user":
            session.get(User, member.user_id).status = "disabled"
        elif invalid == "local":
            recipient = 1
        elif invalid == "missing":
            recipient = 999999
        elif invalid == "cross_org":
            org = Organization(slug="another-team", name="Other")
            session.add(org)
            session.flush()
            session.get(Membership, member.id).organization_id = org.id
        else:
            session.get(Membership, member.id).role = "owner"
            session.get(Membership, member.id).status = "disabled"
        session.commit()
    with database.SessionLocal() as session, pytest.raises(team.TeamAdministrationRejected):
        team.transfer_ownership(session, recipient, **workflow)
    assert len(events(database)) == 1


def test_ordinary_edits_cannot_replace_owner_or_assign_one(administration):
    database, workflow = administration
    member = provision(database, workflow)
    for membership_id, role in [
        (workflow["authorization"].membership_id, "admin"),
        (member.id, "owner"),
    ]:
        with database.SessionLocal() as session, pytest.raises(team.TeamAdministrationRejected):
            team.change_member(session, membership_id, role=role, status="disabled", **workflow)


@pytest.mark.parametrize(
    "limit,offset", [(0, 0), (101, 0), (True, 0), (1, -1), (1, False), (1, 1000001), (1.5, 0)]
)
def test_roster_has_fixed_window_bounds(administration, limit, offset):
    database, workflow = administration
    with database.SessionLocal() as session, pytest.raises(team.TeamAdministrationRejected):
        team.list_members(session, limit=limit, offset=offset, **workflow)


def test_administration_does_not_commit_callers_pending_work(administration):
    database, workflow = administration
    with database.SessionLocal() as session:
        session.add(Organization(slug="pending", name="Pending"))
        with pytest.raises(ValueError, match="fresh session"):
            team.list_members(session, **workflow)
        session.rollback()
    with database.SessionLocal() as session:
        assert session.scalar(select(Organization).where(Organization.slug == "pending")) is None
