import re
import secrets
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest

from sqlalchemy import delete, or_, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.authorization import AuthorizationContext, Role
from app.models import BrowserSession, Membership, User
from app.security_audit import SecurityAction, SecurityOutcome, append_security_event

SESSION_LIFETIME = timedelta(hours=8)
SESSION_IDLE_TIMEOUT = timedelta(minutes=30)
SESSION_TOUCH_INTERVAL = timedelta(minutes=5)
SESSION_ROTATION_INTERVAL = timedelta(hours=1)
MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP = 8
MAX_SESSION_GENERATION = 16
DEFAULT_SESSION_CLEANUP_LIMIT = 256
_TOKEN_BYTES = 32
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


class SessionRejected(RuntimeError):
    """A session cannot be issued for this membership."""


class SessionUnavailable(RuntimeError):
    """The session store could not make a trustworthy decision."""


@dataclass(frozen=True, slots=True)
class IssuedSession:
    session_id: int
    token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class SessionUseResult:
    context: AuthorizationContext
    session_id: int
    replacement: IssuedSession | None = field(default=None, repr=False)


def _now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _digest(token: str) -> str:
    return sha256(token.encode("ascii")).hexdigest()


def _credentials() -> tuple[str, str]:
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    csrf_token = csrf_token_for_session(token)
    if csrf_token is None:  # pragma: no cover - token generator contract guard
        raise SessionRejected("Secure token generation returned an unexpected shape")
    return token, csrf_token


def _authorization_context(
    membership: Membership,
    user: User,
) -> AuthorizationContext | None:
    if membership.status != "active" or user.status != "active":
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


def _is_active(
    browser_session: BrowserSession,
    *,
    now: datetime,
) -> bool:
    return (
        browser_session.replaced_at is None
        and browser_session.revoked_at is None
        and _as_utc(browser_session.token_issued_at) <= now
        and _as_utc(browser_session.last_seen_at) <= now
        and _as_utc(browser_session.expires_at) > now
        and _as_utc(browser_session.last_seen_at) + SESSION_IDLE_TIMEOUT > now
    )


def csrf_token_for_session(token: str) -> str | None:
    """Derive the browser-readable CSRF proof from a valid bearer token."""
    if not is_browser_session_token(token):
        return None
    digest = sha256(b"reddock-csrf-v1\0" + token.encode("ascii")).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def is_browser_session_token(token: str) -> bool:
    return isinstance(token, str) and bool(_TOKEN.fullmatch(token))


def issue_browser_session(
    session: Session,
    membership_id: int,
    *,
    now: datetime | None = None,
) -> IssuedSession:
    """Stage one session family and audit event in the caller's transaction."""

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
    actor = _authorization_context(membership, user)
    if actor is None:
        raise SessionRejected("Active membership required")

    active_sessions = list(
        session.scalars(
            select(BrowserSession)
            .where(
                BrowserSession.membership_id == membership.id,
                BrowserSession.replaced_at.is_(None),
                BrowserSession.revoked_at.is_(None),
                BrowserSession.expires_at > issued_at,
                BrowserSession.last_seen_at > issued_at - SESSION_IDLE_TIMEOUT,
            )
            .order_by(BrowserSession.last_seen_at, BrowserSession.id)
            .with_for_update(of=BrowserSession)
        )
    )
    overflow = len(active_sessions) - MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP + 1
    for stale_session in active_sessions[: max(0, overflow)]:
        session.execute(
            update(BrowserSession)
            .where(
                BrowserSession.family_hash == stale_session.family_hash,
                BrowserSession.revoked_at.is_(None),
            )
            .values(revoked_at=issued_at)
        )

    token, csrf_token = _credentials()
    expires_at = issued_at + SESSION_LIFETIME
    record = BrowserSession(
        token_hash=_digest(token),
        csrf_token_hash=_digest(csrf_token),
        family_hash=secrets.token_hex(_TOKEN_BYTES),
        generation=0,
        membership_id=membership.id,
        created_at=issued_at,
        token_issued_at=issued_at,
        last_seen_at=issued_at,
        expires_at=expires_at,
    )
    session.add(record)
    session.flush()
    append_security_event(
        session,
        organization_id=membership.organization_id,
        actor=actor,
        action=SecurityAction.SESSION_ISSUE,
        outcome=SecurityOutcome.SUCCESS,
        target_type="browser_session",
        target_id=record.family_hash,
        reason_code="session_created",
    )
    session.refresh(record)
    return IssuedSession(
        session_id=record.id,
        token=token,
        csrf_token=csrf_token,
        expires_at=expires_at,
    )


def create_browser_session(
    lifecycle_engine: Engine,
    membership_id: int,
    *,
    now: datetime | None = None,
) -> IssuedSession:
    """Issue and commit one family in an isolated lifecycle transaction."""

    if not isinstance(lifecycle_engine, Engine):
        raise ValueError("a dedicated lifecycle engine is required")
    try:
        with Session(lifecycle_engine) as lifecycle_session:
            with lifecycle_session.begin():
                return issue_browser_session(lifecycle_session, membership_id, now=now)
    except SessionRejected:
        raise
    except SQLAlchemyError as error:
        raise SessionUnavailable("browser session store is unavailable") from error


def _session_row(
    session: Session,
    token_hash: str,
) -> tuple[BrowserSession, Membership, User] | None:
    row = session.execute(
        select(BrowserSession, Membership, User)
        .join(Membership, Membership.id == BrowserSession.membership_id)
        .join(User, User.id == Membership.user_id)
        .where(BrowserSession.token_hash == token_hash)
        .execution_options(populate_existing=True)
    ).one_or_none()
    return row


def resolve_browser_session(
    session: Session,
    token: str,
    *,
    csrf_token: str | None = None,
    now: datetime | None = None,
    touch: bool = False,
) -> AuthorizationContext | None:
    """Resolve a token and optionally stage a throttled touch without committing."""

    if not is_browser_session_token(token):
        return None
    resolved_at = _as_utc(now or _now())
    token_hash = _digest(token)
    row = _session_row(session, token_hash)
    if row is None:
        return None
    browser_session, membership, user = row
    context = _authorization_context(membership, user)
    if context is None or not _is_active(browser_session, now=resolved_at):
        return None
    if csrf_token is not None and not csrf_token_matches(
        csrf_token, browser_session.csrf_token_hash
    ):
        return None
    stored_last_seen = _as_utc(browser_session.last_seen_at)
    if not touch or stored_last_seen > resolved_at - SESSION_TOUCH_INTERVAL:
        return context
    result = session.execute(
        update(BrowserSession)
        .where(
            BrowserSession.id == browser_session.id,
            BrowserSession.token_hash == token_hash,
            BrowserSession.replaced_at.is_(None),
            BrowserSession.revoked_at.is_(None),
            BrowserSession.expires_at > resolved_at,
            BrowserSession.last_seen_at > resolved_at - SESSION_IDLE_TIMEOUT,
            BrowserSession.last_seen_at <= resolved_at - SESSION_TOUCH_INTERVAL,
            BrowserSession.last_seen_at < resolved_at,
        )
        .values(last_seen_at=resolved_at)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount:
        session.expire(browser_session, ["last_seen_at"])
        return context

    # A concurrent touch may have won. Re-read every validity predicate; a
    # concurrent revoke, rotation, or expiry must never be mistaken for success.
    row = _session_row(session, token_hash)
    if row is None:
        return None
    browser_session, membership, user = row
    context = _authorization_context(membership, user)
    if context is None or not _is_active(browser_session, now=resolved_at):
        return None
    if csrf_token is not None and not csrf_token_matches(
        csrf_token, browser_session.csrf_token_hash
    ):
        return None
    return context


def _locked_family(
    session: Session,
    token_hash: str,
) -> tuple[BrowserSession, Membership, User, list[BrowserSession]] | None:
    locator = session.scalar(
        select(BrowserSession).where(BrowserSession.token_hash == token_hash)
    )
    if locator is None:
        return None
    identity = session.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.id == locator.membership_id)
        .with_for_update()
    ).one_or_none()
    if identity is None:
        return None
    membership, user = identity
    family = list(
        session.scalars(
            select(BrowserSession)
            .where(BrowserSession.family_hash == locator.family_hash)
            .order_by(BrowserSession.id)
            .with_for_update(of=BrowserSession)
            .execution_options(populate_existing=True)
        )
    )
    presented = next((item for item in family if item.token_hash == token_hash), None)
    if presented is None:
        return None
    return presented, membership, user, family


def rotate_browser_session(
    session: Session,
    token: str,
    csrf_token: str,
    *,
    now: datetime | None = None,
) -> IssuedSession | None:
    """Stage one due token rotation in the caller's transaction.

    ``None`` means a valid session does not need rotation yet. Invalid or stale
    credentials raise ``SessionRejected`` without revealing which check failed.
    """

    if not is_browser_session_token(token) or not is_browser_session_token(csrf_token):
        raise SessionRejected("Browser session is invalid")
    rotated_at = _as_utc(now or _now())
    locked = _locked_family(session, _digest(token))
    if locked is None:
        raise SessionRejected("Browser session is invalid")
    current, membership, user, _family = locked
    actor = _authorization_context(membership, user)
    if (
        actor is None
        or not _is_active(current, now=rotated_at)
        or not csrf_token_matches(csrf_token, current.csrf_token_hash)
    ):
        raise SessionRejected("Browser session is invalid")
    if _as_utc(current.token_issued_at) + SESSION_ROTATION_INTERVAL > rotated_at:
        return None
    if current.generation >= MAX_SESSION_GENERATION:
        raise SessionRejected("Browser session is invalid")

    current.replaced_at = rotated_at
    session.flush()
    token, csrf_token = _credentials()
    successor = BrowserSession(
        token_hash=_digest(token),
        csrf_token_hash=_digest(csrf_token),
        family_hash=current.family_hash,
        generation=current.generation + 1,
        membership_id=current.membership_id,
        created_at=rotated_at,
        token_issued_at=rotated_at,
        last_seen_at=rotated_at,
        expires_at=current.expires_at,
    )
    session.add(successor)
    session.flush()
    append_security_event(
        session,
        organization_id=membership.organization_id,
        actor=actor,
        action=SecurityAction.SESSION_ROTATE,
        outcome=SecurityOutcome.SUCCESS,
        target_type="browser_session",
        target_id=successor.family_hash,
        reason_code="session_rotated",
    )
    session.refresh(successor)
    return IssuedSession(
        session_id=successor.id,
        token=token,
        csrf_token=csrf_token,
        expires_at=_as_utc(successor.expires_at),
    )


def use_browser_session(
    lifecycle_engine: Engine,
    token: str,
    *,
    csrf_token: str | None = None,
    rotate_if_due: bool = False,
    now: datetime | None = None,
) -> SessionUseResult | None:
    """Resolve, touch, and optionally rotate inside one isolated transaction."""

    if not isinstance(lifecycle_engine, Engine):
        raise ValueError("a dedicated lifecycle engine is required")
    if rotate_if_due and csrf_token is None:
        raise ValueError("rotation requires a CSRF proof")
    checked_at = _as_utc(now or _now())
    try:
        with Session(lifecycle_engine) as lifecycle_session:
            with lifecycle_session.begin():
                replacement = None
                if rotate_if_due:
                    replacement = rotate_browser_session(
                        lifecycle_session,
                        token,
                        csrf_token or "",
                        now=checked_at,
                    )
                active_token = replacement.token if replacement is not None else token
                active_csrf = replacement.csrf_token if replacement is not None else csrf_token
                context = resolve_browser_session(
                    lifecycle_session,
                    active_token,
                    csrf_token=active_csrf,
                    now=checked_at,
                    touch=True,
                )
                if context is None:
                    raise SessionRejected("Browser session is invalid")
                session_id = (
                    replacement.session_id
                    if replacement is not None
                    else lifecycle_session.scalar(
                        select(BrowserSession.id).where(
                            BrowserSession.token_hash == _digest(active_token)
                        )
                    )
                )
                if session_id is None:
                    raise SessionRejected("Browser session is invalid")
                result = SessionUseResult(
                    context=context,
                    session_id=session_id,
                    replacement=replacement,
                )
        return result
    except SessionRejected:
        return None
    except SQLAlchemyError as error:
        raise SessionUnavailable("browser session store is unavailable") from error


def csrf_token_matches(presented: str, expected_hash: str) -> bool:
    if not is_browser_session_token(presented) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_hash
    ):
        return False
    return compare_digest(_digest(presented), expected_hash)


def revoke_browser_session(
    session: Session,
    token: str,
    *,
    now: datetime | None = None,
) -> bool:
    """Stage family-wide logout for a current or retained predecessor token."""

    if not is_browser_session_token(token):
        return False
    revoked_at = _as_utc(now or _now())
    locked = _locked_family(session, _digest(token))
    if locked is None:
        return False
    presented, membership, user, family = locked
    active = [
        item
        for item in family
        if item.replaced_at is None and item.revoked_at is None
    ]
    if not active:
        return False
    for item in family:
        if item.revoked_at is None:
            item.revoked_at = revoked_at
    is_predecessor = presented.replaced_at is not None
    actor = None if is_predecessor else _authorization_context(membership, user)
    append_security_event(
        session,
        organization_id=membership.organization_id,
        actor=actor,
        action=(
            SecurityAction.SESSION_REPLAY
            if is_predecessor
            else SecurityAction.SESSION_REVOKE
        ),
        outcome=(
            SecurityOutcome.DENIED if is_predecessor else SecurityOutcome.SUCCESS
        ),
        target_type="browser_session_family",
        target_id=presented.family_hash,
        reason_code=(
            "superseded_token_contained" if is_predecessor else "session_logout"
        ),
    )
    return True


def logout_browser_session(
    lifecycle_engine: Engine,
    token: str,
    *,
    now: datetime | None = None,
) -> bool:
    """Commit family-wide logout in an isolated lifecycle transaction."""

    if not isinstance(lifecycle_engine, Engine):
        raise ValueError("a dedicated lifecycle engine is required")
    try:
        with Session(lifecycle_engine) as lifecycle_session:
            with lifecycle_session.begin():
                return revoke_browser_session(lifecycle_session, token, now=now)
    except SQLAlchemyError as error:
        raise SessionUnavailable("browser session store is unavailable") from error


def revoke_membership_sessions(
    session: Session,
    membership_id: int,
    *,
    now: datetime | None = None,
) -> int:
    """Stage family revocation for composition with an identity change."""

    revoked_at = _as_utc(now or _now())
    membership = session.scalar(
        select(Membership)
        .where(Membership.id == membership_id)
        .with_for_update(of=Membership)
    )
    if membership is None:
        return 0
    records = list(
        session.scalars(
            select(BrowserSession)
            .where(BrowserSession.membership_id == membership_id)
            .order_by(BrowserSession.id)
            .with_for_update(of=BrowserSession)
        )
    )
    active_families = {
        item.family_hash
        for item in records
        if item.replaced_at is None and item.revoked_at is None
    }
    for item in records:
        if item.family_hash in active_families and item.revoked_at is None:
            item.revoked_at = revoked_at
    session.flush()
    return len(active_families)


def purge_inactive_browser_sessions(
    session: Session,
    *,
    before: datetime,
    limit: int = DEFAULT_SESSION_CLEANUP_LIMIT,
) -> int:
    """Stage one bounded cleanup batch without deleting active lineage."""

    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
        raise ValueError("session cleanup count must be between 1 and 1000")
    cutoff = _as_utc(before)
    idle_cutoff = cutoff - SESSION_IDLE_TIMEOUT
    inactive = or_(
        BrowserSession.expires_at <= cutoff,
        BrowserSession.revoked_at <= cutoff,
        (
            BrowserSession.replaced_at.is_(None)
            & (BrowserSession.last_seen_at <= idle_cutoff)
        ),
    )
    inactive_ids = (
        select(BrowserSession.id)
        .where(inactive)
        .order_by(BrowserSession.id)
        .limit(limit)
    )
    if session.get_bind().dialect.name == "postgresql":
        inactive_ids = inactive_ids.with_for_update(skip_locked=True)
    result = session.execute(
        delete(BrowserSession).where(
            inactive,
            BrowserSession.id.in_(inactive_ids),
        )
    )
    return result.rowcount or 0
