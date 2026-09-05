from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from app.models import BrowserSession, Membership, User
from app.session_auth import (
    SESSION_LIFETIME,
    SessionRejected,
    csrf_token_matches,
    issue_browser_session,
    resolve_browser_session,
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
