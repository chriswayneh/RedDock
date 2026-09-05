from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.models import BrowserSession, Membership, User
from app.session_auth import (
    MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP,
    SESSION_LIFETIME,
    SessionRejected,
    csrf_token_matches,
    issue_browser_session,
    purge_inactive_browser_sessions,
    resolve_browser_session,
    revoke_browser_session,
    revoke_membership_sessions,
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
    assert issued.expires_at == NOW + SESSION_LIFETIME
    assert csrf_token_matches(issued.csrf_token, stored.csrf_token_hash)

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
