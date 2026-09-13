"""Database-serialized limits for future authenticated server traffic.

The shipped local application does not call this module. Future server routes
must consume the verified client address produced by TrustedIngressMiddleware,
never a forwarding header supplied directly by a client. Server integration
must provide a dedicated Engine whose connection pool is reserved for limiter
transactions so request work cannot starve the security decision.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from hmac import new as hmac_new
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from math import ceil

from sqlalchemy import case, delete, or_, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import RateLimitBucket

MAX_BUCKET_ATTEMPTS = 1_000_000
MAX_WINDOW = timedelta(days=1)
DEFAULT_CLEANUP_LIMIT = 64
_SESSION_HASH = re.compile(r"[0-9a-f]{64}")


class RateLimitedAction(StrEnum):
    OIDC_LOGIN = "oidc.login"
    OIDC_CALLBACK = "oidc.callback"
    REQUEST_MUTATION = "request.mutation"


class RateLimitScope(StrEnum):
    GLOBAL = "global"
    CLIENT = "client"
    MEMBERSHIP = "membership"
    SESSION = "session"


class RateLimitUnavailable(RuntimeError):
    """The durable limiter could not make a trustworthy decision."""


@dataclass(frozen=True, slots=True)
class RateLimitKey:
    """Deployment-owned HMAC material shared by every application worker."""

    material: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.material, bytes) or not 32 <= len(self.material) <= 128:
            raise ValueError("rate-limit key must contain 32 to 128 bytes")


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    limit: int
    window: timedelta

    def __post_init__(self) -> None:
        if not isinstance(self.window, timedelta):
            raise ValueError("rate-limit window must be a duration")
        seconds = self.window.total_seconds()
        if (
            isinstance(self.limit, bool)
            or not isinstance(self.limit, int)
            or not 1 <= self.limit <= MAX_BUCKET_ATTEMPTS
        ):
            raise ValueError("rate-limit count must be between 1 and 1000000")
        if seconds != int(seconds) or not 1 <= seconds <= MAX_WINDOW.total_seconds():
            raise ValueError("rate-limit window must be 1 to 86400 whole seconds")


@dataclass(frozen=True, slots=True)
class RateLimitPlan:
    action: RateLimitedAction
    global_rule: RateLimitRule
    subject_rule: RateLimitRule

    def __post_init__(self) -> None:
        if (
            not isinstance(self.action, RateLimitedAction)
            or not isinstance(self.global_rule, RateLimitRule)
            or not isinstance(self.subject_rule, RateLimitRule)
        ):
            raise ValueError("rate-limit plan must use a supported action and bounded rules")


@dataclass(frozen=True, slots=True)
class RateLimitSubject:
    scope: RateLimitScope
    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.scope, RateLimitScope) or not isinstance(self.value, str):
            raise ValueError("rate-limit subject is invalid")
        if self.scope is RateLimitScope.GLOBAL:
            if self.value != "global":
                raise ValueError("global rate-limit subject is invalid")
        elif (
            not self.value
            or len(self.value) > 128
            or not self.value.isascii()
            or "\0" in self.value
        ):
            raise ValueError("rate-limit subject is invalid")


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int


OIDC_LOGIN_PLAN = RateLimitPlan(
    action=RateLimitedAction.OIDC_LOGIN,
    global_rule=RateLimitRule(limit=512, window=timedelta(minutes=10)),
    subject_rule=RateLimitRule(limit=10, window=timedelta(minutes=10)),
)
OIDC_CALLBACK_PLAN = RateLimitPlan(
    action=RateLimitedAction.OIDC_CALLBACK,
    global_rule=RateLimitRule(limit=1_024, window=timedelta(minutes=10)),
    subject_rule=RateLimitRule(limit=20, window=timedelta(minutes=10)),
)
REQUEST_MUTATION_PLAN = RateLimitPlan(
    action=RateLimitedAction.REQUEST_MUTATION,
    global_rule=RateLimitRule(limit=4_096, window=timedelta(minutes=1)),
    subject_rule=RateLimitRule(limit=120, window=timedelta(minutes=1)),
)

_GLOBAL_SUBJECT = RateLimitSubject(RateLimitScope.GLOBAL, "global")


def _now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)


def client_subject(verified_client_ip: str) -> RateLimitSubject:
    """Normalize only the canonical address already verified at trusted ingress."""
    try:
        address = ip_address(verified_client_ip)
    except ValueError as error:
        raise ValueError("verified client address is invalid") from error
    if str(address) != verified_client_ip:
        raise ValueError("verified client address must be canonical")
    if isinstance(address, IPv4Address):
        value = str(address)
    elif isinstance(address, IPv6Address):
        value = str(ip_network(f"{address}/64", strict=False))
    else:  # pragma: no cover - ipaddress currently has only v4 and v6
        raise ValueError("verified client address family is unsupported")
    return RateLimitSubject(RateLimitScope.CLIENT, value)


def membership_subject(membership_id: int) -> RateLimitSubject:
    if (
        isinstance(membership_id, bool)
        or not isinstance(membership_id, int)
        or not 1 <= membership_id <= 2**63 - 1
    ):
        raise ValueError("membership identifier is invalid")
    return RateLimitSubject(RateLimitScope.MEMBERSHIP, str(membership_id))


def session_subject(session_token_hash: str) -> RateLimitSubject:
    if not isinstance(session_token_hash, str) or not _SESSION_HASH.fullmatch(session_token_hash):
        raise ValueError("session identifier hash is invalid")
    return RateLimitSubject(RateLimitScope.SESSION, session_token_hash)


def _key_hash(
    action: RateLimitedAction,
    subject: RateLimitSubject,
    key: RateLimitKey,
) -> str:
    material = (
        b"reddock-rate-limit-v1\0"
        + action.value.encode("ascii")
        + b"\0"
        + subject.scope.value.encode("ascii")
        + b"\0"
        + subject.value.encode("ascii")
    )
    return hmac_new(key.material, material, sha256).hexdigest()


def _retry_after(expires_at: datetime, now: datetime, window: timedelta) -> int:
    remaining = ceil((_as_utc(expires_at) - now).total_seconds())
    return max(1, min(remaining, int(window.total_seconds())))


def _consume(
    session: Session,
    *,
    plan: RateLimitPlan,
    subject: RateLimitSubject,
    rule: RateLimitRule,
    key: RateLimitKey,
    now: datetime,
) -> RateLimitDecision:
    table = RateLimitBucket.__table__
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        statement = postgresql_insert(table)
    elif dialect == "sqlite":
        statement = sqlite_insert(table)
    else:
        raise RateLimitUnavailable("database dialect does not support atomic rate limiting")

    key_hash = _key_hash(plan.action, subject, key)
    expires_at = now + rule.window
    expired = table.c.expires_at <= now
    statement = (
        statement.values(
            action=plan.action.value,
            key_hash=key_hash,
            attempt_count=1,
            expires_at=expires_at,
        )
        .on_conflict_do_update(
            index_elements=[table.c.action, table.c.key_hash],
            set_={
                "attempt_count": case((expired, 1), else_=table.c.attempt_count + 1),
                "expires_at": case((expired, expires_at), else_=table.c.expires_at),
            },
            where=or_(expired, table.c.attempt_count < rule.limit),
        )
        .returning(table.c.attempt_count, table.c.expires_at)
    )

    row = session.execute(statement).one_or_none()
    if row is not None:
        return RateLimitDecision(allowed=True, retry_after_seconds=0)

    stored_expiry = session.scalar(
        select(table.c.expires_at).where(
            table.c.action == plan.action.value,
            table.c.key_hash == key_hash,
        )
    )
    if stored_expiry is None:
        raise RateLimitUnavailable("rate-limit decision lost its durable bucket")
    return RateLimitDecision(
        allowed=False,
        retry_after_seconds=_retry_after(stored_expiry, now, rule.window),
    )


def purge_expired_rate_limit_buckets(
    session: Session,
    *,
    before: datetime,
    limit: int = DEFAULT_CLEANUP_LIMIT,
) -> int:
    """Delete one bounded batch inside the caller's current transaction."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
        raise ValueError("rate-limit cleanup count must be between 1 and 1000")
    cutoff = _as_utc(before)
    table = RateLimitBucket.__table__
    expired_ids = (
        select(table.c.id)
        .where(table.c.expires_at <= cutoff)
        .order_by(table.c.expires_at, table.c.id)
        .limit(limit)
    )
    if session.get_bind().dialect.name == "postgresql":
        expired_ids = expired_ids.with_for_update(skip_locked=True)
    result = session.execute(
        delete(table).where(
            table.c.expires_at <= cutoff,
            table.c.id.in_(expired_ids),
        )
    )
    return result.rowcount or 0


def enforce_rate_limit(
    limiter_engine: Engine,
    plan: RateLimitPlan,
    *,
    subject: RateLimitSubject,
    key: RateLimitKey,
    now: datetime | None = None,
) -> RateLimitDecision:
    """Own and commit one isolated global-first limiter transaction."""
    if not isinstance(subject, RateLimitSubject) or subject.scope is RateLimitScope.GLOBAL:
        raise ValueError("a non-global rate-limit subject is required")
    if not isinstance(limiter_engine, Engine) or not isinstance(key, RateLimitKey):
        raise ValueError("a dedicated limiter engine and rate-limit key are required")
    checked_at = _as_utc(now or _now())
    try:
        with Session(limiter_engine) as limiter_session:
            try:
                global_decision = _consume(
                    limiter_session,
                    plan=plan,
                    subject=_GLOBAL_SUBJECT,
                    rule=plan.global_rule,
                    key=key,
                    now=checked_at,
                )
                if not global_decision.allowed:
                    limiter_session.commit()
                    return global_decision

                purge_expired_rate_limit_buckets(limiter_session, before=checked_at)
                subject_decision = _consume(
                    limiter_session,
                    plan=plan,
                    subject=subject,
                    rule=plan.subject_rule,
                    key=key,
                    now=checked_at,
                )
                limiter_session.commit()
                return subject_decision
            except RateLimitUnavailable:
                limiter_session.rollback()
                raise
            except SQLAlchemyError as error:
                limiter_session.rollback()
                raise RateLimitUnavailable("durable rate limiter is unavailable") from error
    except SQLAlchemyError as error:
        raise RateLimitUnavailable("durable rate limiter is unavailable") from error
