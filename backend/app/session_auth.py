import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest

from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import Session

from app.authorization import AuthorizationContext, Role
from app.models import BrowserSession, Membership, User
from app.security_audit import SecurityAction, SecurityOutcome, append_security_event

SESSION_LIFETIME = timedelta(hours=8)
MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP = 8
_TOKEN_BYTES = 32
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


class SessionRejected(RuntimeError):
    """A session cannot be issued for this membership."""


@dataclass(frozen=True, slots=True)
class IssuedSession:
    session_id: int
    token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    expires_at: datetime


def _now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _digest(token: str) -> str:
    return sha256(token.encode("ascii")).hexdigest()


def _valid_token(token: str) -> bool:
    return bool(_TOKEN.fullmatch(token))


def issue_browser_session(
    session: Session,
    membership_id: int,
    *,
    now: datetime | None = None,
) -> IssuedSession:
    issued_at = _as_utc(now or _now())
    identity = session.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.id == membership_id)
        .with_for_update(of=Membership)
    ).one_or_none()
    if identity is None:
        raise SessionRejected("Active membership required")
    membership, user = identity
    try:
        Role(membership.role)
    except ValueError as error:
        raise SessionRejected("Active membership required") from error
    if membership.status != "active" or user.status != "active":
        raise SessionRejected("Active membership required")

    active_sessions = list(
        session.scalars(
            select(BrowserSession)
            .where(
                BrowserSession.membership_id == membership.id,
                BrowserSession.revoked_at.is_(None),
                BrowserSession.expires_at > issued_at,
            )
            .order_by(BrowserSession.last_seen_at, BrowserSession.id)
        )
    )
    overflow = len(active_sessions) - MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP + 1
    for stale_session in active_sessions[: max(0, overflow)]:
        stale_session.revoked_at = issued_at

    token = secrets.token_urlsafe(_TOKEN_BYTES)
    csrf_token = secrets.token_urlsafe(_TOKEN_BYTES)
    expires_at = issued_at + SESSION_LIFETIME
    record = BrowserSession(
        token_hash=_digest(token),
        csrf_token_hash=_digest(csrf_token),
        membership_id=membership.id,
        last_seen_at=issued_at,
        expires_at=expires_at,
    )
    session.add(record)
    session.flush()
    append_security_event(
        session,
        organization_id=membership.organization_id,
        actor=AuthorizationContext(
            organization_id=membership.organization_id,
            user_id=membership.user_id,
            membership_id=membership.id,
            role=Role(membership.role),
        ),
        action=SecurityAction.SESSION_ISSUE,
        outcome=SecurityOutcome.SUCCESS,
        target_type="browser_session",
        target_id=str(record.id),
        reason_code="session_created",
    )
    session.commit()
    session.refresh(record)
    return IssuedSession(
        session_id=record.id,
        token=token,
        csrf_token=csrf_token,
        expires_at=expires_at,
    )


def resolve_browser_session(
    session: Session,
    token: str,
    *,
    now: datetime | None = None,
) -> AuthorizationContext | None:
    if not _valid_token(token):
        return None
    resolved_at = _as_utc(now or _now())
    row = session.execute(
        select(BrowserSession, Membership, User)
        .join(Membership, Membership.id == BrowserSession.membership_id)
        .join(User, User.id == Membership.user_id)
        .where(BrowserSession.token_hash == _digest(token))
    ).one_or_none()
    if row is None:
        return None
    browser_session, membership, user = row
    if (
        browser_session.revoked_at is not None
        or _as_utc(browser_session.expires_at) <= resolved_at
        or membership.status != "active"
        or user.status != "active"
    ):
        return None
    try:
        role = Role(membership.role)
    except ValueError:
        return None
    return AuthorizationContext(
        organization_id=membership.organization_id,
        user_id=membership.user_id,
        membership_id=membership.id,
        role=role,
    )


def csrf_token_matches(presented: str, expected_hash: str) -> bool:
    if not _valid_token(presented) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        return False
    return compare_digest(_digest(presented), expected_hash)


def revoke_browser_session(
    session: Session,
    token: str,
    *,
    now: datetime | None = None,
) -> bool:
    """Revoke one bearer token without storing or querying its plaintext value."""
    if not _valid_token(token):
        return False
    revoked_at = _as_utc(now or _now())
    row = session.execute(
        select(BrowserSession, Membership)
        .join(Membership, Membership.id == BrowserSession.membership_id)
        .where(BrowserSession.token_hash == _digest(token))
        .with_for_update(of=BrowserSession)
    ).one_or_none()
    if row is None or row[0].revoked_at is not None:
        return False
    browser_session, membership = row
    browser_session.revoked_at = revoked_at
    try:
        role = Role(membership.role)
    except ValueError:
        actor = None
    else:
        actor = AuthorizationContext(
            organization_id=membership.organization_id,
            user_id=membership.user_id,
            membership_id=membership.id,
            role=role,
        )
    append_security_event(
        session,
        organization_id=membership.organization_id,
        actor=actor,
        action=SecurityAction.SESSION_REVOKE,
        outcome=SecurityOutcome.SUCCESS,
        target_type="browser_session",
        target_id=str(browser_session.id),
        reason_code="session_logout",
    )
    session.commit()
    return True


def revoke_membership_sessions(
    session: Session,
    membership_id: int,
    *,
    now: datetime | None = None,
) -> int:
    """Revoke every live session after a role, access, or account change."""
    revoked_at = _as_utc(now or _now())
    result = session.execute(
        update(BrowserSession)
        .where(
            BrowserSession.membership_id == membership_id,
            BrowserSession.revoked_at.is_(None),
        )
        .values(revoked_at=revoked_at)
    )
    session.commit()
    return result.rowcount or 0


def purge_inactive_browser_sessions(
    session: Session,
    *,
    before: datetime,
) -> int:
    """Delete expired or revoked records older than an operator-selected cutoff."""
    cutoff = _as_utc(before)
    result = session.execute(
        delete(BrowserSession).where(
            or_(
                BrowserSession.expires_at <= cutoff,
                BrowserSession.revoked_at <= cutoff,
            )
        )
    )
    session.commit()
    return result.rowcount or 0
