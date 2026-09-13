import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import func, inspect, select


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
                == "0005_rate_limits"
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
