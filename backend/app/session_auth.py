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

SESSION_LIFETIME = timedelta(hours=8)
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
    result = session.execute(
        update(BrowserSession)
        .where(
            BrowserSession.token_hash == _digest(token),
            BrowserSession.revoked_at.is_(None),
        )
        .values(revoked_at=revoked_at)
    )
    session.commit()
    return result.rowcount == 1


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
