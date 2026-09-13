from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.models import BrowserSession, Membership, User
from app.security_audit import list_security_events
from app.session_auth import (
    MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP,
    SESSION_IDLE_TIMEOUT,
    SESSION_LIFETIME,
    SESSION_ROTATION_INTERVAL,
    SESSION_TOUCH_INTERVAL,
    SessionRejected,
    SessionUnavailable,
    create_browser_session,
    csrf_token_for_session,
    csrf_token_matches,
    issue_browser_session,
    logout_browser_session,
    purge_inactive_browser_sessions,
    resolve_browser_session,
    revoke_browser_session,
    revoke_membership_sessions,
    rotate_browser_session,
    use_browser_session,
)

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


def test_issued_session_stores_hashes_and_resolves_the_membership(session: Session):
    issued = issue_browser_session(session, 1, now=NOW)
    stored = session.get(BrowserSession, issued.session_id)

    assert stored is not None
    assert issued.token not in repr(issued)
    assert issued.csrf_token not in repr(issued)
    assert stored.token_hash != issued.token
    assert stored.csrf_token_hash != issued.csrf_token
    assert len(stored.token_hash) == len(stored.csrf_token_hash) == 64
    assert len(stored.family_hash) == 64
    assert stored.generation == 0
    assert stored.created_at.replace(tzinfo=UTC) == NOW
    assert stored.token_issued_at.replace(tzinfo=UTC) == NOW
    assert issued.expires_at == NOW + SESSION_LIFETIME
    assert csrf_token_matches(issued.csrf_token, stored.csrf_token_hash)
    assert csrf_token_for_session(issued.token) == issued.csrf_token
    assert csrf_token_for_session("short") is None

    context = resolve_browser_session(session, issued.token, now=NOW)
    assert context is not None
    assert (
        context.organization_id,
        context.user_id,
        context.membership_id,
        context.role,
    ) == (1, 1, 1, "owner")


def test_malformed_unknown_expired_and_revoked_tokens_are_rejected(session: Session):
    issued = issue_browser_session(session, 1, now=NOW)
    stored = session.get(BrowserSession, issued.session_id)
    assert stored is not None

    assert resolve_browser_session(session, "short", now=NOW) is None
    assert resolve_browser_session(session, "A" * 43, now=NOW) is None
    assert resolve_browser_session(session, issued.token, now=issued.expires_at) is None
    stored.revoked_at = NOW
    session.commit()
    assert resolve_browser_session(session, issued.token, now=NOW) is None


def test_idle_expiry_and_throttled_touch_use_exact_boundaries(session: Session):
    issued = issue_browser_session(session, 1, now=NOW)
    stored = session.get(BrowserSession, issued.session_id)
    assert stored is not None

    before_touch = NOW + SESSION_TOUCH_INTERVAL - timedelta(microseconds=1)
    assert resolve_browser_session(session, issued.token, now=before_touch, touch=True)
    session.refresh(stored)
    assert stored.last_seen_at.replace(tzinfo=UTC) == NOW

    touch_at = NOW + SESSION_TOUCH_INTERVAL
    assert resolve_browser_session(session, issued.token, now=touch_at, touch=True)
    session.refresh(stored)
    assert stored.last_seen_at.replace(tzinfo=UTC) == touch_at

    just_before_idle = touch_at + SESSION_IDLE_TIMEOUT - timedelta(microseconds=1)
    assert resolve_browser_session(session, issued.token, now=just_before_idle)
    assert resolve_browser_session(
        session,
        issued.token,
        now=touch_at + SESSION_IDLE_TIMEOUT,
        touch=True,
    ) is None
    session.refresh(stored)
    assert stored.last_seen_at.replace(tzinfo=UTC) == touch_at


def test_invalid_proof_and_clock_regression_fail_closed_without_touch(session: Session):
    issued = issue_browser_session(session, 1, now=NOW)
    stored = session.get(BrowserSession, issued.session_id)
    assert stored is not None

    assert resolve_browser_session(
        session,
        issued.token,
        csrf_token="A" * 43,
        now=NOW + SESSION_TOUCH_INTERVAL,
        touch=True,
    ) is None
    assert (
        resolve_browser_session(
            session,
            issued.token,
            now=NOW - timedelta(minutes=1),
            touch=True,
        )
        is None
    )
    session.refresh(stored)
    assert stored.last_seen_at.replace(tzinfo=UTC) == NOW


@pytest.mark.parametrize("record_type", ["membership", "user"])
def test_disabled_identity_invalidates_an_existing_session(session: Session, record_type: str):
    issued = issue_browser_session(session, 1, now=NOW)
    record = session.get(Membership if record_type == "membership" else User, 1)
    assert record is not None
    record.status = "disabled"
    session.commit()

    assert resolve_browser_session(session, issued.token, now=NOW) is None


def test_session_issuance_requires_an_active_membership(session: Session):
    membership = session.get(Membership, 1)
    assert membership is not None
    membership.status = "disabled"
    session.commit()

    with pytest.raises(SessionRejected, match="Active membership required"):
        issue_browser_session(session, 1, now=NOW)
    with pytest.raises(SessionRejected, match="Active membership required"):
        issue_browser_session(session, 999_999, now=NOW)


def test_csrf_comparison_rejects_malformed_values(session: Session):
    issued = issue_browser_session(session, 1, now=NOW)
    stored = session.get(BrowserSession, issued.session_id)
    assert stored is not None

    assert not csrf_token_matches("short", stored.csrf_token_hash)
    assert not csrf_token_matches(issued.csrf_token, "not-a-sha256")
    assert not csrf_token_matches("A" * 43, stored.csrf_token_hash)


def test_logout_revocation_is_hash_only_and_idempotent(session: Session):
    issued = issue_browser_session(session, 1, now=NOW)

    assert not revoke_browser_session(session, "short", now=NOW)
    assert not revoke_browser_session(session, "A" * 43, now=NOW)
    assert revoke_browser_session(session, issued.token, now=NOW)
    assert not revoke_browser_session(session, issued.token, now=NOW)
    assert resolve_browser_session(session, issued.token, now=NOW) is None
    assert [event.action for event in list_security_events(session, 1)] == [
        "session.revoke",
        "session.issue",
    ]


def _keep_session_active_until_rotation(
    session: Session,
    token: str,
) -> None:
    for minutes in (25, 50):
        assert resolve_browser_session(
            session,
            token,
            now=NOW + timedelta(minutes=minutes),
            touch=True,
        )


def test_rotation_replaces_bearer_and_csrf_without_extending_absolute_expiry(
    session: Session,
):
    issued = issue_browser_session(session, 1, now=NOW)
    _keep_session_active_until_rotation(session, issued.token)
    before_due = NOW + SESSION_ROTATION_INTERVAL - timedelta(microseconds=1)
    assert (
        rotate_browser_session(
            session,
            issued.token,
            issued.csrf_token,
            now=before_due,
        )
        is None
    )

    rotated_at = NOW + SESSION_ROTATION_INTERVAL
    replacement = rotate_browser_session(
        session,
        issued.token,
        issued.csrf_token,
        now=rotated_at,
    )
    assert replacement is not None
    assert replacement.token != issued.token
    assert replacement.csrf_token != issued.csrf_token
    assert replacement.expires_at == issued.expires_at
    assert resolve_browser_session(session, issued.token, now=rotated_at) is None
    assert resolve_browser_session(
        session,
        replacement.token,
        csrf_token=replacement.csrf_token,
        now=rotated_at,
    )
    assert (
        resolve_browser_session(
            session,
            replacement.token,
            csrf_token=issued.csrf_token,
            now=rotated_at,
        )
        is None
    )

    predecessor = session.get(BrowserSession, issued.session_id)
    successor = session.get(BrowserSession, replacement.session_id)
    assert predecessor is not None and successor is not None
    assert predecessor.replaced_at.replace(tzinfo=UTC) == rotated_at
    assert predecessor.family_hash == successor.family_hash
    assert (predecessor.generation, successor.generation) == (0, 1)
    assert successor.expires_at.replace(tzinfo=UTC) == issued.expires_at
    assert [event.action for event in list_security_events(session, 1)][:2] == [
        "session.rotate",
        "session.issue",
    ]


def test_predecessor_logout_revokes_the_rotated_family(session: Session):
    issued = issue_browser_session(session, 1, now=NOW)
    _keep_session_active_until_rotation(session, issued.token)
    replacement = rotate_browser_session(
        session,
        issued.token,
        issued.csrf_token,
        now=NOW + SESSION_ROTATION_INTERVAL,
    )
    assert replacement is not None

    assert revoke_browser_session(
        session,
        issued.token,
        now=NOW + SESSION_ROTATION_INTERVAL + timedelta(seconds=1),
    )
    assert (
        resolve_browser_session(
            session,
            replacement.token,
            now=NOW + SESSION_ROTATION_INTERVAL + timedelta(seconds=1),
        )
        is None
    )
    family = list(
        session.scalars(
            select(BrowserSession).where(
                BrowserSession.family_hash
                == session.get(BrowserSession, issued.session_id).family_hash
            )
        )
    )
    assert len(family) == 2
    assert all(item.revoked_at is not None for item in family)
    replay_event = list_security_events(session, 1)[0]
    assert replay_event.action == "session.replay"
    assert replay_event.outcome == "denied"
    assert replay_event.actor_user_id is None
    assert replay_event.actor_membership_id is None
    assert replay_event.target_id == family[0].family_hash
    assert replay_event.reason_code == "superseded_token_contained"


def test_membership_revocation_invalidates_all_of_its_sessions(session: Session):
    other_user = User(
        oidc_issuer="https://issuer.example",
        oidc_subject="other-user",
        display_name="Other user",
        status="active",
    )
    session.add(other_user)
    session.flush()
    other_membership = Membership(
        organization_id=1,
        user_id=other_user.id,
        role="viewer",
        status="active",
    )
    session.add(other_membership)
    session.commit()

    first = issue_browser_session(session, 1, now=NOW)
    second = issue_browser_session(session, 1, now=NOW)
    unaffected = issue_browser_session(session, other_membership.id, now=NOW)

    assert revoke_membership_sessions(session, 1, now=NOW) == 2
    assert revoke_membership_sessions(session, 1, now=NOW) == 0
    assert resolve_browser_session(session, first.token, now=NOW) is None
    assert resolve_browser_session(session, second.token, now=NOW) is None
    assert resolve_browser_session(session, unaffected.token, now=NOW) is not None


def test_cleanup_removes_only_inactive_sessions_at_the_cutoff(session: Session):
    expired = issue_browser_session(session, 1, now=NOW - SESSION_LIFETIME)
    revoked = issue_browser_session(session, 1, now=NOW)
    active = issue_browser_session(session, 1, now=NOW)
    assert revoke_browser_session(session, revoked.token, now=NOW)

    assert purge_inactive_browser_sessions(session, before=NOW) == 2
    assert session.get(BrowserSession, expired.session_id) is None
    assert session.get(BrowserSession, revoked.session_id) is None
    assert session.get(BrowserSession, active.session_id) is not None


def test_cleanup_is_bounded_and_retains_live_rotation_lineage(session: Session):
    issued = issue_browser_session(session, 1, now=NOW)
    _keep_session_active_until_rotation(session, issued.token)
    replacement = rotate_browser_session(
        session,
        issued.token,
        issued.csrf_token,
        now=NOW + SESSION_ROTATION_INTERVAL,
    )
    assert replacement is not None

    cleanup_at = NOW + SESSION_ROTATION_INTERVAL
    assert purge_inactive_browser_sessions(session, before=cleanup_at, limit=1) == 0
    assert session.get(BrowserSession, issued.session_id) is not None
    assert session.get(BrowserSession, replacement.session_id) is not None

    expired_at = issued.expires_at
    assert purge_inactive_browser_sessions(session, before=expired_at, limit=1) == 1
    assert session.scalar(select(func.count(BrowserSession.id))) == 1
    assert purge_inactive_browser_sessions(session, before=expired_at, limit=1) == 1
    assert session.scalar(select(func.count(BrowserSession.id))) == 0


@pytest.mark.parametrize("limit", [0, 1001, True, 1.5])
def test_cleanup_rejects_invalid_batch_sizes(session: Session, limit):
    with pytest.raises(ValueError, match="between 1 and 1000"):
        purge_inactive_browser_sessions(session, before=NOW, limit=limit)


def test_session_mutators_are_transaction_neutral(session: Session):
    issued = issue_browser_session(session, 1, now=NOW)
    issued_id = issued.session_id
    session.rollback()
    assert session.get(BrowserSession, issued_id) is None

    committed = issue_browser_session(session, 1, now=NOW)
    session.commit()
    assert revoke_browser_session(session, committed.token, now=NOW)
    session.rollback()
    assert resolve_browser_session(session, committed.token, now=NOW) is not None

    assert revoke_membership_sessions(session, 1, now=NOW) == 1
    session.rollback()
    assert resolve_browser_session(session, committed.token, now=NOW) is not None


def test_engine_owned_issuance_commits_before_returning(session: Session):
    lifecycle_engine = session.get_bind()
    session.rollback()

    issued = create_browser_session(lifecycle_engine, 1, now=NOW)
    with Session(lifecycle_engine) as verifier:
        stored = verifier.get(BrowserSession, issued.session_id)
        assert stored is not None
        assert resolve_browser_session(verifier, issued.token, now=NOW) is not None


def test_engine_owned_use_rotation_and_logout_commit_before_returning(session: Session):
    lifecycle_engine = session.get_bind()
    session.rollback()
    issued = create_browser_session(lifecycle_engine, 1, now=NOW)

    for minutes in (5, 25, 50):
        result = use_browser_session(
            lifecycle_engine,
            issued.token,
            now=NOW + timedelta(minutes=minutes),
        )
        assert result is not None and result.replacement is None

    result = use_browser_session(
        lifecycle_engine,
        issued.token,
        csrf_token=issued.csrf_token,
        rotate_if_due=True,
        now=NOW + SESSION_ROTATION_INTERVAL,
    )
    assert result is not None and result.replacement is not None
    replacement = result.replacement
    with Session(lifecycle_engine) as verifier:
        assert resolve_browser_session(verifier, issued.token, now=NOW) is None
        assert resolve_browser_session(
            verifier,
            replacement.token,
            now=NOW + SESSION_ROTATION_INTERVAL,
        )

    assert logout_browser_session(
        lifecycle_engine,
        issued.token,
        now=NOW + SESSION_ROTATION_INTERVAL + timedelta(seconds=1),
    )
    with Session(lifecycle_engine) as verifier:
        assert (
            resolve_browser_session(
                verifier,
                replacement.token,
                now=NOW + SESSION_ROTATION_INTERVAL + timedelta(seconds=1),
            )
            is None
        )


@pytest.mark.parametrize(
    "operation",
    [
        lambda engine: create_browser_session(engine, 1, now=NOW),
        lambda engine: use_browser_session(engine, "A" * 43, now=NOW),
        lambda engine: logout_browser_session(engine, "A" * 43, now=NOW),
    ],
)
def test_engine_owned_operations_fail_closed_on_database_errors(
    session: Session,
    monkeypatch: pytest.MonkeyPatch,
    operation,
):
    import app.session_auth

    lifecycle_engine = session.get_bind()

    class BrokenSession:
        def __init__(self, _engine):
            raise OperationalError("session operation", {}, RuntimeError("offline"))

    monkeypatch.setattr(app.session_auth, "Session", BrokenSession)
    with pytest.raises(SessionUnavailable, match="store is unavailable"):
        operation(lifecycle_engine)


def test_issuing_a_session_revokes_the_oldest_above_the_active_limit(session: Session):
    issued = [
        issue_browser_session(session, 1, now=NOW + timedelta(minutes=index))
        for index in range(MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP + 1)
    ]
    checked_at = NOW + timedelta(minutes=MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP)

    assert resolve_browser_session(session, issued[0].token, now=checked_at) is None
    assert all(
        resolve_browser_session(session, item.token, now=checked_at) is not None
        for item in issued[1:]
    )
    active_count = sum(
        record.revoked_at is None for record in session.query(BrowserSession).all()
    )
    assert active_count == MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP
