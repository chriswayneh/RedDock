from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.schema import DropTable

from app.models import RateLimitBucket
from app.rate_limits import (
    RateLimitedAction,
    RateLimiterRuntime,
    RateLimitKey,
    RateLimitPlan,
    RateLimitRule,
    RateLimitScope,
    RateLimitSubject,
    RateLimitUnavailable,
    client_subject,
    enforce_rate_limit,
    membership_subject,
    purge_expired_rate_limit_buckets,
    session_subject,
)

NOW = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
KEY = RateLimitKey(b"unit-test-rate-limit-key-material")


def _plan(
    *,
    action: RateLimitedAction = RateLimitedAction.OIDC_LOGIN,
    global_limit: int = 100,
    subject_limit: int = 2,
    seconds: int = 60,
) -> RateLimitPlan:
    return RateLimitPlan(
        action=action,
        global_rule=RateLimitRule(global_limit, timedelta(seconds=seconds)),
        subject_rule=RateLimitRule(subject_limit, timedelta(seconds=seconds)),
    )


def _enforce(session, plan, *, subject, now=NOW, key=KEY):
    return enforce_rate_limit(session.get_bind(), plan, subject=subject, key=key, now=now)


def test_subject_limit_denies_after_exact_limit_and_resets_at_expiry(session):
    plan = _plan(subject_limit=2)
    subject = client_subject("192.0.2.15")

    assert _enforce(session, plan, subject=subject).allowed
    assert _enforce(session, plan, subject=subject).allowed
    denied = _enforce(session, plan, subject=subject)
    assert denied.allowed is False
    assert denied.retry_after_seconds == 60

    reset = _enforce(session, plan, subject=subject, now=NOW + timedelta(seconds=60))
    assert reset.allowed
    rows = list(session.scalars(select(RateLimitBucket)))
    assert sorted(row.attempt_count for row in rows) == [1, 1]


def test_actions_and_subjects_have_independent_buckets(session):
    first = client_subject("192.0.2.20")
    second = client_subject("192.0.2.21")
    login = _plan(subject_limit=1)
    callback = _plan(action=RateLimitedAction.OIDC_CALLBACK, subject_limit=1)

    assert _enforce(session, login, subject=first).allowed
    assert not _enforce(session, login, subject=first).allowed
    assert _enforce(session, login, subject=second).allowed
    assert _enforce(session, callback, subject=first).allowed


def test_global_denial_does_not_create_an_attacker_selected_subject_bucket(session):
    plan = _plan(global_limit=1, subject_limit=10)
    assert _enforce(session, plan, subject=client_subject("192.0.2.30")).allowed

    denied = _enforce(session, plan, subject=client_subject("192.0.2.31"))
    assert denied.allowed is False
    assert session.scalar(select(func.count()).select_from(RateLimitBucket)) == 2


def test_client_subjects_are_canonical_and_ipv6_is_aggregated_to_64(session):
    plan = _plan(subject_limit=1)
    first = client_subject("2001:db8:abcd:12::1")
    second = client_subject("2001:db8:abcd:12::ffff")

    assert repr(first) == "RateLimitSubject(scope=<RateLimitScope.CLIENT: 'client'>)"
    assert _enforce(session, plan, subject=first).allowed
    assert not _enforce(session, plan, subject=second).allowed

    for invalid in ("2001:0db8::1", "192.168.001.1", "not-an-address", "192.0.2.1 "):
        with pytest.raises(ValueError, match="client address"):
            client_subject(invalid)


def test_keyed_subjects_are_not_stored_or_recoverable_with_another_key(session):
    raw_ip = "198.51.100.42"
    subject = client_subject(raw_ip)
    assert raw_ip not in repr(subject)
    assert _enforce(session, _plan(), subject=subject).allowed

    rows = list(session.scalars(select(RateLimitBucket)))
    assert len(rows) == 2
    assert all(raw_ip not in repr(row) for row in rows)
    assert all(raw_ip not in row.key_hash for row in rows)
    assert all(len(row.key_hash) == 64 for row in rows)
    first_hashes = {row.key_hash for row in rows}

    session.execute(RateLimitBucket.__table__.delete())
    session.commit()
    another_key = RateLimitKey(b"another-independent-limiter-key-1")
    assert _enforce(session, _plan(), subject=subject, key=another_key).allowed
    second_hashes = set(session.scalars(select(RateLimitBucket.key_hash)))
    assert first_hashes.isdisjoint(second_hashes)


def test_bounded_cleanup_preserves_active_rows_and_drains_in_batches(session):
    for index in range(70):
        session.add(
            RateLimitBucket(
                action=RateLimitedAction.OIDC_LOGIN.value,
                key_hash=sha256(f"expired-{index}".encode()).hexdigest(),
                attempt_count=1,
                expires_at=NOW - timedelta(seconds=1),
            )
        )
    session.add(
        RateLimitBucket(
            action=RateLimitedAction.OIDC_LOGIN.value,
            key_hash=sha256(b"active").hexdigest(),
            attempt_count=1,
            expires_at=NOW + timedelta(seconds=1),
        )
    )
    session.commit()

    assert purge_expired_rate_limit_buckets(session, before=NOW) == 64
    assert session.scalar(select(func.count()).select_from(RateLimitBucket)) == 7
    assert purge_expired_rate_limit_buckets(session, before=NOW) == 6
    session.commit()
    assert session.scalar(select(func.count()).select_from(RateLimitBucket)) == 1


def test_database_errors_roll_back_and_fail_closed(session):
    engine = session.get_bind()
    session.execute(RateLimitBucket.__table__.delete())
    session.commit()
    session.execute(DropTable(RateLimitBucket.__table__))
    session.commit()

    with pytest.raises(RateLimitUnavailable, match="unavailable"):
        enforce_rate_limit(
            engine,
            _plan(),
            subject=client_subject("192.0.2.40"),
            key=KEY,
            now=NOW,
        )
    assert not session.in_transaction()


def test_subject_failure_rolls_back_the_global_bucket(session, monkeypatch):
    import app.rate_limits

    original_consume = app.rate_limits._consume
    calls = 0

    def fail_after_global(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise SQLAlchemyError("synthetic subject failure")
        return original_consume(*args, **kwargs)

    monkeypatch.setattr(app.rate_limits, "_consume", fail_after_global)

    with pytest.raises(RateLimitUnavailable, match="unavailable") as error:
        _enforce(session, _plan(), subject=client_subject("192.0.2.42"))

    assert error.value.__cause__ is None
    assert session.scalar(select(func.count()).select_from(RateLimitBucket)) == 0


def test_limiter_transaction_cannot_commit_unrelated_caller_state(session):
    from sqlalchemy.orm import Session

    from app.models import Organization

    pending = Organization(slug="still-pending", name="Caller-owned state")
    session.add(pending)

    assert _enforce(session, _plan(), subject=client_subject("192.0.2.41")).allowed
    assert pending in session.new
    with Session(session.get_bind()) as verifier:
        assert (
            verifier.scalar(select(Organization).where(Organization.slug == "still-pending"))
            is None
        )
    session.rollback()


@pytest.mark.parametrize(
    ("factory", "value"),
    [
        (membership_subject, 0),
        (membership_subject, True),
        (membership_subject, "1"),
        (session_subject, "A" * 64),
        (session_subject, "short"),
    ],
)
def test_non_client_subject_factories_reject_invalid_values(factory, value):
    with pytest.raises(ValueError):
        factory(value)


def test_rate_limit_configuration_is_bounded_and_code_owned():
    with pytest.raises(ValueError):
        RateLimitKey(b"short")
    with pytest.raises(ValueError):
        RateLimitRule(0, timedelta(seconds=1))
    with pytest.raises(ValueError):
        RateLimitRule(1, timedelta(0))
    with pytest.raises(ValueError):
        RateLimitRule(1, timedelta(days=2))
    with pytest.raises(ValueError):
        RateLimitRule(1, timedelta(milliseconds=1))
    with pytest.raises(ValueError):
        RateLimitSubject(RateLimitScope.GLOBAL, "client-controlled")
    with pytest.raises(ValueError):
        RateLimitPlan(
            "oidc.login",
            RateLimitRule(1, timedelta(seconds=1)),
            RateLimitRule(1, timedelta(seconds=1)),
        )
    with pytest.raises(ValueError):
        RateLimitPlan(RateLimitedAction.OIDC_LOGIN, "global", "subject")


def test_runtime_keeps_the_key_and_engine_paired_and_closes_idempotently(session):
    runtime = RateLimiterRuntime(session.get_bind(), KEY)
    assert repr(runtime) == "RateLimiterRuntime(closed=False)"
    assert runtime.enforce(_plan(), subject=client_subject("192.0.2.50"), now=NOW).allowed

    runtime.close()
    runtime.close()
    assert repr(runtime) == "RateLimiterRuntime(closed=True)"
    with pytest.raises(RateLimitUnavailable, match="unavailable"):
        runtime.enforce(_plan(), subject=client_subject("192.0.2.50"), now=NOW)
