import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import delete, func, inspect, select


def test_postgresql_migrations_and_crud(tmp_path, monkeypatch: pytest.MonkeyPatch):
    url = os.getenv("REDDOCK_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("REDDOCK_TEST_POSTGRES_URL is not configured")

    import app.config
    import app.database
    from app.models import Dockyard

    monkeypatch.setenv("REDDOCK_DATABASE_URL", url)
    monkeypatch.setenv("REDDOCK_EVIDENCE_DIR", str(tmp_path / "evidence"))
    for name in (
        "REDDOCK_DATABASE_HOST",
        "REDDOCK_DATABASE_PORT",
        "REDDOCK_DATABASE_NAME",
        "REDDOCK_DATABASE_USER",
        "REDDOCK_DATABASE_PASSWORD_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    app.config.get_settings.cache_clear()
    app.database.configure_engine()

    try:
        app.database.initialize_database()
        assert app.database.engine.dialect.name == "postgresql"
        assert inspect(app.database.engine).has_table("dockyards")
        assert inspect(app.database.engine).has_table("security_audit_events")
        assert inspect(app.database.engine).has_table("oidc_login_attempts")
        assert inspect(app.database.engine).has_table("rate_limit_buckets")
        from app.migration_runner import _config

        with app.database.engine.begin() as connection:
            command.downgrade(_config(connection), "0005_rate_limits")
            connection.exec_driver_sql(
                """
                INSERT INTO browser_sessions (
                    token_hash, csrf_token_hash, membership_id, created_at,
                    last_seen_at, expires_at, revoked_at
                ) VALUES (
                    repeat('a', 64), repeat('b', 64), 1,
                    '2026-09-13 12:00:01+00', '2026-09-13 12:00:00+00',
                    '2026-09-13 13:00:00+00', NULL
                )
                """
            )
        app.database.initialize_database()
        with app.database.engine.begin() as connection:
            normalized = connection.exec_driver_sql(
                """
                SELECT created_at, last_seen_at, token_issued_at
                FROM browser_sessions WHERE token_hash = repeat('a', 64)
                """
            ).mappings().one()
            assert normalized["created_at"] == normalized["last_seen_at"]
            assert normalized["token_issued_at"] == normalized["last_seen_at"]
            connection.exec_driver_sql(
                "DELETE FROM browser_sessions WHERE token_hash = repeat('a', 64)"
            )

        with app.database.engine.begin() as connection:
            command.downgrade(_config(connection), "0004_oidc_attempts")
            connection.exec_driver_sql(
                """
                CREATE TABLE rate_limit_buckets (
                    id SERIAL PRIMARY KEY,
                    action VARCHAR(48) NOT NULL,
                    key_hash VARCHAR(64) NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    CONSTRAINT ck_rate_limit_action CHECK (
                        action IN ('oidc.login', 'oidc.callback', 'request.mutation')
                    ),
                    CONSTRAINT ck_rate_limit_key_hash CHECK (length(key_hash) = 64),
                    CONSTRAINT ck_rate_limit_attempt_count CHECK (
                        attempt_count BETWEEN 1 AND 1000000
                    ),
                    CONSTRAINT uq_rate_limit_bucket UNIQUE (action, key_hash)
                )
                """
            )
            connection.exec_driver_sql(
                "CREATE INDEX ix_rate_limit_expiry ON rate_limit_buckets (expires_at, id)"
            )

        # No released schema contains this table at revision 0004. Refuse even a
        # convincing look-alike rather than stamp database objects RedDock did not create.
        with pytest.raises(RuntimeError, match="Unexpected preexisting rate_limit_buckets table"):
            app.database.initialize_database()
        with app.database.engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE rate_limit_buckets")
        app.database.initialize_database()
        with app.database.engine.begin() as connection:
            assert (
                connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
                == "0006_session_lifecycle"
            )
            assert (
                connection.exec_driver_sql(
                    "INSERT INTO organizations (slug, name) "
                    "VALUES ('sequence-check', 'Sequence check') RETURNING id"
                ).scalar_one()
                == 2
            )

        from app.models import RateLimitBucket
        from app.rate_limits import (
            RateLimitedAction,
            RateLimitKey,
            RateLimitPlan,
            RateLimitRule,
            client_subject,
            enforce_rate_limit,
            purge_expired_rate_limit_buckets,
        )

        workers = 16
        barrier = Barrier(workers)
        limited_at = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
        plan = RateLimitPlan(
            action=RateLimitedAction.OIDC_LOGIN,
            global_rule=RateLimitRule(5, timedelta(minutes=1)),
            subject_rule=RateLimitRule(1, timedelta(minutes=1)),
        )
        limiter_key = RateLimitKey(b"postgres-integration-limiter-key")

        def attempt(index: int, checked_at: datetime) -> bool:
            barrier.wait(timeout=15)
            return enforce_rate_limit(
                app.database.engine,
                plan,
                subject=client_subject(f"192.0.2.{index + 1}"),
                key=limiter_key,
                now=checked_at,
            ).allowed

        with ThreadPoolExecutor(max_workers=workers) as executor:
            first_window = list(
                executor.map(lambda index: attempt(index, limited_at), range(workers))
            )
        assert sum(first_window) == 5
        with app.database.SessionLocal() as session:
            rows = list(session.scalars(select(RateLimitBucket)))
            assert len(rows) == 6
            assert sorted(row.attempt_count for row in rows) == [1, 1, 1, 1, 1, 5]

        barrier = Barrier(workers)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            second_window = list(
                executor.map(
                    lambda index: attempt(index + 100, limited_at + timedelta(minutes=1)),
                    range(workers),
                )
            )
        assert sum(second_window) == 5
        with app.database.SessionLocal() as session:
            rows = list(session.scalars(select(RateLimitBucket)))
            assert len(rows) == 6
            assert session.scalar(select(func.max(RateLimitBucket.attempt_count))) == 5

        same_subject_plan = RateLimitPlan(
            action=RateLimitedAction.OIDC_CALLBACK,
            global_rule=RateLimitRule(workers, timedelta(minutes=1)),
            subject_rule=RateLimitRule(5, timedelta(minutes=1)),
        )
        barrier = Barrier(workers)

        def same_subject_attempt(_: int) -> bool:
            barrier.wait(timeout=15)
            return enforce_rate_limit(
                app.database.engine,
                same_subject_plan,
                subject=client_subject("198.51.100.10"),
                key=limiter_key,
                now=limited_at,
            ).allowed

        with ThreadPoolExecutor(max_workers=workers) as executor:
            same_subject = list(executor.map(same_subject_attempt, range(workers)))
        assert sum(same_subject) == 5
        with app.database.SessionLocal() as session:
            rows = list(
                session.scalars(
                    select(RateLimitBucket).where(
                        RateLimitBucket.action == RateLimitedAction.OIDC_CALLBACK.value
                    )
                )
            )
            assert sorted(row.attempt_count for row in rows) == [5, workers]

        cleanup_plan = RateLimitPlan(
            action=RateLimitedAction.REQUEST_MUTATION,
            global_rule=RateLimitRule(10, timedelta(minutes=1)),
            subject_rule=RateLimitRule(10, timedelta(minutes=1)),
        )
        cleanup_subject = client_subject("203.0.113.20")
        assert enforce_rate_limit(
            app.database.engine,
            cleanup_plan,
            subject=cleanup_subject,
            key=limiter_key,
            now=limited_at,
        ).allowed
        cleanup_barrier = Barrier(2)

        def cleanup_expired() -> int:
            with app.database.SessionLocal() as cleanup_session:
                cleanup_barrier.wait(timeout=15)
                deleted = purge_expired_rate_limit_buckets(
                    cleanup_session,
                    before=limited_at + timedelta(minutes=1),
                )
                cleanup_session.commit()
                return deleted

        def refresh_expired() -> bool:
            cleanup_barrier.wait(timeout=15)
            return enforce_rate_limit(
                app.database.engine,
                cleanup_plan,
                subject=cleanup_subject,
                key=limiter_key,
                now=limited_at + timedelta(minutes=1),
            ).allowed

        with ThreadPoolExecutor(max_workers=2) as executor:
            cleanup_future = executor.submit(cleanup_expired)
            refresh_future = executor.submit(refresh_expired)
            assert refresh_future.result(timeout=15)
            assert cleanup_future.result(timeout=15) <= 64
        with app.database.SessionLocal() as session:
            rows = list(
                session.scalars(
                    select(RateLimitBucket).where(
                        RateLimitBucket.action == RateLimitedAction.REQUEST_MUTATION.value
                    )
                )
            )
            assert len(rows) == 2
            assert all(row.expires_at == limited_at + timedelta(minutes=2) for row in rows)
            assert sorted(row.attempt_count for row in rows) == [1, 1]

        from app.models import BrowserSession, Membership
        from app.session_auth import (
            MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP,
            SESSION_IDLE_TIMEOUT,
            SESSION_ROTATION_INTERVAL,
            SESSION_TOUCH_INTERVAL,
            create_browser_session,
            logout_browser_session,
            purge_inactive_browser_sessions,
            revoke_membership_sessions,
            use_browser_session,
        )

        session_time = datetime(2026, 9, 13, 14, 0, tzinfo=UTC)

        def clear_browser_sessions() -> None:
            with app.database.SessionLocal.begin() as session:
                session.execute(delete(BrowserSession))

        def rotatable_session(offset: timedelta):
            issued_at = session_time + offset
            issued = create_browser_session(app.database.engine, 1, now=issued_at)
            assert use_browser_session(
                app.database.engine,
                issued.token,
                now=issued_at + timedelta(minutes=25),
            )
            assert use_browser_session(
                app.database.engine,
                issued.token,
                now=issued_at + timedelta(minutes=50),
            )
            return issued, issued_at + SESSION_ROTATION_INTERVAL

        clear_browser_sessions()
        issue_workers = MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP + 4
        issue_barrier = Barrier(issue_workers)

        def concurrent_issue(_: int):
            issue_barrier.wait(timeout=15)
            return create_browser_session(app.database.engine, 1, now=session_time)

        with ThreadPoolExecutor(max_workers=issue_workers) as executor:
            issued_sessions = list(executor.map(concurrent_issue, range(issue_workers)))
        assert len({issued.session_id for issued in issued_sessions}) == issue_workers
        with app.database.SessionLocal() as session:
            active_count = session.scalar(
                select(func.count(BrowserSession.id)).where(
                    BrowserSession.membership_id == 1,
                    BrowserSession.replaced_at.is_(None),
                    BrowserSession.revoked_at.is_(None),
                )
            )
            assert active_count == MAX_ACTIVE_SESSIONS_PER_MEMBERSHIP

        clear_browser_sessions()
        rotation_source, rotation_time = rotatable_session(timedelta(hours=2))
        rotation_barrier = Barrier(2)

        def rotate_same_token():
            rotation_barrier.wait(timeout=15)
            return use_browser_session(
                app.database.engine,
                rotation_source.token,
                csrf_token=rotation_source.csrf_token,
                rotate_if_due=True,
                now=rotation_time,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            same_token_results = list(executor.map(lambda _: rotate_same_token(), range(2)))
        assert sum(result is not None for result in same_token_results) == 1
        rotation_winner = next(result for result in same_token_results if result is not None)
        assert rotation_winner.replacement is not None
        with app.database.SessionLocal() as session:
            family_hash = session.scalar(
                select(BrowserSession.family_hash).where(
                    BrowserSession.id == rotation_source.session_id
                )
            )
            family = list(
                session.scalars(
                    select(BrowserSession)
                    .where(BrowserSession.family_hash == family_hash)
                    .order_by(BrowserSession.generation)
                )
            )
            assert [record.generation for record in family] == [0, 1]
            assert family[0].replaced_at == rotation_time
            assert family[1].replaced_at is None
            assert family[1].revoked_at is None
        with app.database.SessionLocal.begin() as session:
            assert (
                purge_inactive_browser_sessions(
                    session,
                    before=rotation_time + SESSION_IDLE_TIMEOUT + timedelta(seconds=1),
                )
                == 1
            )
            assert session.get(BrowserSession, rotation_source.session_id) is not None
            assert session.get(BrowserSession, rotation_winner.session_id) is None

        clear_browser_sessions()
        logout_source, logout_time = rotatable_session(timedelta(hours=4))
        logout_barrier = Barrier(2)

        def rotate_during_logout():
            logout_barrier.wait(timeout=15)
            return use_browser_session(
                app.database.engine,
                logout_source.token,
                csrf_token=logout_source.csrf_token,
                rotate_if_due=True,
                now=logout_time,
            )

        def logout_during_rotation() -> bool:
            logout_barrier.wait(timeout=15)
            return logout_browser_session(
                app.database.engine,
                logout_source.token,
                now=logout_time,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            rotation_future = executor.submit(rotate_during_logout)
            logout_future = executor.submit(logout_during_rotation)
            logout_rotation_result = rotation_future.result(timeout=15)
            assert logout_future.result(timeout=15)
        with app.database.SessionLocal() as session:
            family_hash = session.scalar(
                select(BrowserSession.family_hash).where(
                    BrowserSession.id == logout_source.session_id
                )
            )
            logout_family = list(
                session.scalars(
                    select(BrowserSession).where(BrowserSession.family_hash == family_hash)
                )
            )
            assert all(record.revoked_at == logout_time for record in logout_family)
            assert not any(
                record.replaced_at is None and record.revoked_at is None
                for record in logout_family
            )
        if logout_rotation_result is not None:
            assert logout_rotation_result.replacement is not None
            assert (
                use_browser_session(
                    app.database.engine,
                    logout_rotation_result.replacement.token,
                    now=logout_time,
                )
                is None
            )

        clear_browser_sessions()
        revocation_source, revocation_time = rotatable_session(timedelta(hours=6))
        revocation_barrier = Barrier(2)

        def rotate_during_membership_revocation():
            revocation_barrier.wait(timeout=15)
            return use_browser_session(
                app.database.engine,
                revocation_source.token,
                csrf_token=revocation_source.csrf_token,
                rotate_if_due=True,
                now=revocation_time,
            )

        def revoke_membership_during_rotation() -> int:
            revocation_barrier.wait(timeout=15)
            with app.database.SessionLocal.begin() as session:
                revoked = revoke_membership_sessions(session, 1, now=revocation_time)
                membership = session.get(Membership, 1)
                assert membership is not None
                membership.status = "disabled"
                return revoked

        with ThreadPoolExecutor(max_workers=2) as executor:
            rotation_future = executor.submit(rotate_during_membership_revocation)
            revocation_future = executor.submit(revoke_membership_during_rotation)
            membership_rotation_result = rotation_future.result(timeout=15)
            assert revocation_future.result(timeout=15) == 1
        with app.database.SessionLocal() as session:
            assert session.get(Membership, 1).status == "disabled"
            family_hash = session.scalar(
                select(BrowserSession.family_hash).where(
                    BrowserSession.id == revocation_source.session_id
                )
            )
            revocation_family = list(
                session.scalars(
                    select(BrowserSession).where(BrowserSession.family_hash == family_hash)
                )
            )
            assert all(record.revoked_at == revocation_time for record in revocation_family)
            assert not any(
                record.replaced_at is None and record.revoked_at is None
                for record in revocation_family
            )
        if membership_rotation_result is not None:
            assert membership_rotation_result.replacement is not None
            assert (
                use_browser_session(
                    app.database.engine,
                    membership_rotation_result.replacement.token,
                    now=revocation_time,
                )
                is None
            )
        with app.database.SessionLocal.begin() as session:
            membership = session.get(Membership, 1)
            assert membership is not None
            membership.status = "active"
            session.execute(delete(BrowserSession))

        touch_source = create_browser_session(
            app.database.engine,
            1,
            now=session_time + timedelta(hours=8),
        )
        touch_time = (
            session_time + timedelta(hours=8) + SESSION_TOUCH_INTERVAL
        )
        touch_barrier = Barrier(2)

        def concurrent_touch():
            touch_barrier.wait(timeout=15)
            return use_browser_session(
                app.database.engine,
                touch_source.token,
                now=touch_time,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            touch_results = list(executor.map(lambda _: concurrent_touch(), range(2)))
        assert all(result is not None for result in touch_results)
        with app.database.SessionLocal() as session:
            touched = session.get(BrowserSession, touch_source.session_id)
            assert touched is not None
            assert touched.last_seen_at == touch_time

        clear_browser_sessions()
        cleanup_issued_at = session_time + timedelta(hours=10)
        cleanup_source = create_browser_session(
            app.database.engine,
            1,
            now=cleanup_issued_at,
        )
        cleanup_cutoff = cleanup_issued_at + SESSION_IDLE_TIMEOUT
        cleanup_use_time = cleanup_cutoff - timedelta(seconds=1)
        session_cleanup_barrier = Barrier(2)

        def use_during_session_cleanup():
            session_cleanup_barrier.wait(timeout=15)
            return use_browser_session(
                app.database.engine,
                cleanup_source.token,
                now=cleanup_use_time,
            )

        def cleanup_during_session_use() -> int:
            session_cleanup_barrier.wait(timeout=15)
            with app.database.SessionLocal.begin() as session:
                return purge_inactive_browser_sessions(
                    session,
                    before=cleanup_cutoff,
                )

        with ThreadPoolExecutor(max_workers=2) as executor:
            use_future = executor.submit(use_during_session_cleanup)
            cleanup_future = executor.submit(cleanup_during_session_use)
            cleanup_use_result = use_future.result(timeout=15)
            cleanup_deleted = cleanup_future.result(timeout=15)
        with app.database.SessionLocal() as session:
            surviving_session = session.get(BrowserSession, cleanup_source.session_id)
            if cleanup_use_result is not None:
                assert cleanup_deleted == 0
                assert surviving_session is not None
                assert surviving_session.last_seen_at == cleanup_use_time
            else:
                assert cleanup_deleted == 1
                assert surviving_session is None
        clear_browser_sessions()

        marker = f"PostgreSQL integration {uuid4()}"
        with app.database.SessionLocal() as session:
            dockyard = Dockyard(name=marker, description="CI migration and CRUD proof")
            session.add(dockyard)
            session.commit()
            dockyard_id = dockyard.id

        with app.database.SessionLocal() as session:
            stored = session.scalar(select(Dockyard).where(Dockyard.id == dockyard_id))
            assert stored is not None
            assert stored.name == marker
            assert stored.organization_id == 1
            session.delete(stored)
            session.commit()

        # Exercise reporting against the real server: another connection
        # commits a scope change after source capture starts. The report must
        # retain the earlier snapshot across its subsequent SELECT statements.
        from app.models import ScopeEntry
        from app.reporting import runner
        from tests.phase1 import Recorder
        from tests.test_reporting import _prepared

        with app.database.SessionLocal() as session:
            dockyard = Dockyard(name="PostgreSQL reporting isolation")
            session.add(dockyard)
            session.commit()
            report_dockyard_id = dockyard.id
            _prepared(Recorder(session, dockyard.id), session, dockyard.id, tmp_path)

        original_snapshot = runner._snapshot

        def concurrent_scope_change(session, dockyard_id, manifest):
            with app.database.SessionLocal() as writer:
                writer.add(
                    ScopeEntry(
                        dockyard_id=dockyard_id, rule="exclude", kind="ipv4", value="192.0.2.1"
                    )
                )
                writer.commit()
            snapshot = original_snapshot(session, dockyard_id, manifest)
            assert snapshot["scope"] == []
            return snapshot

        monkeypatch.setattr(runner, "_snapshot", concurrent_scope_change)
        with app.database.SessionLocal() as session:
            report = runner.start_report(session, report_dockyard_id)
            assert report.status == "completed", report.error
        with app.database.SessionLocal() as session:
            assert (
                session.scalar(
                    select(ScopeEntry).where(ScopeEntry.dockyard_id == report_dockyard_id)
                ).value
                == "192.0.2.1"
            )
    finally:
        monkeypatch.setenv("REDDOCK_DATABASE_URL", f"sqlite:///{tmp_path / 'after-postgres.db'}")
        app.config.get_settings.cache_clear()
        app.database.configure_engine()
