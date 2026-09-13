from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.config import DormantServerRuntimeConfig, get_settings
from app.orm import Base as Base

POSTGRES_APPLICATION_POOL_SIZE = 5
POSTGRES_APPLICATION_MAX_OVERFLOW = 10
POSTGRES_APPLICATION_POOL_TIMEOUT_SECONDS = 5
POSTGRES_LIMITER_POOL_SIZE = 2
POSTGRES_LIMITER_POOL_TIMEOUT_SECONDS = 2
POSTGRES_CONNECT_TIMEOUT_SECONDS = 5
POSTGRES_LIMITER_STATEMENT_TIMEOUT_MS = 2_000
POSTGRES_LIMITER_LOCK_TIMEOUT_MS = 1_000


def _connect_args(database_url: str | URL) -> dict:
    backend = database_url.drivername if isinstance(database_url, URL) else database_url
    if str(backend).startswith("sqlite"):
        # Discovery runs write from a background thread, so the connection is shared
        # across threads and a short lock wait avoids spurious "database is locked".
        return {"check_same_thread": False, "timeout": 15}
    if str(backend).startswith("postgresql"):
        return {
            "connect_timeout": POSTGRES_CONNECT_TIMEOUT_SECONDS,
            "application_name": "reddock-app",
        }
    return {}


def _database_url(settings) -> str | URL:
    if settings.database_password is not None:
        return URL.create(
            "postgresql+psycopg",
            username=settings.database_user,
            password=settings.database_password.get_secret_value(),
            host=settings.database_host,
            port=settings.database_port,
            database=settings.database_name,
        )
    return settings.database_url


def _application_engine(url: str | URL) -> Engine:
    options: dict[str, object] = {"connect_args": _connect_args(url)}
    backend = url.drivername if isinstance(url, URL) else url
    if str(backend).startswith("postgresql"):
        options.update(
            pool_size=POSTGRES_APPLICATION_POOL_SIZE,
            max_overflow=POSTGRES_APPLICATION_MAX_OVERFLOW,
            pool_timeout=POSTGRES_APPLICATION_POOL_TIMEOUT_SECONDS,
            pool_pre_ping=True,
        )
    return create_engine(url, **options)


engine: Engine
SessionLocal = sessionmaker(autoflush=False, autocommit=False)


def configure_engine() -> None:
    """(Re)build the engine from current settings and rebind the session maker."""
    global engine
    previous = globals().get("engine")
    settings = get_settings()
    candidate = _application_engine(_database_url(settings))
    engine = candidate
    SessionLocal.configure(bind=engine)
    if previous is not None:
        previous.dispose()


def create_rate_limiter_runtime(config: DormantServerRuntimeConfig):
    """Build and prime one isolated PostgreSQL limiter capability."""

    from app.rate_limits import RateLimiterRuntime, RateLimitKey, RateLimitUnavailable

    if not isinstance(config, DormantServerRuntimeConfig):
        raise ValueError("validated dormant server runtime configuration is required")
    url = URL.create(
        "postgresql+psycopg",
        username=config.database_user,
        password=config.database_password.get_secret_value(),
        host=config.database_host,
        port=config.database_port,
        database=config.database_name,
    )
    try:
        limiter_engine = create_engine(
            url,
            pool_size=POSTGRES_LIMITER_POOL_SIZE,
            max_overflow=0,
            pool_timeout=POSTGRES_LIMITER_POOL_TIMEOUT_SECONDS,
            pool_pre_ping=True,
            isolation_level="READ COMMITTED",
            connect_args={
                "connect_timeout": POSTGRES_CONNECT_TIMEOUT_SECONDS,
                "application_name": "reddock-limiter",
                "options": (
                    f"-c statement_timeout={POSTGRES_LIMITER_STATEMENT_TIMEOUT_MS} "
                    f"-c lock_timeout={POSTGRES_LIMITER_LOCK_TIMEOUT_MS}"
                ),
            },
        )
    except SQLAlchemyError:
        raise RateLimitUnavailable("durable rate limiter is unavailable") from None
    runtime = RateLimiterRuntime(
        limiter_engine,
        RateLimitKey(config.rate_limit_key.get_secret_value()),
    )
    try:
        with ExitStack() as stack:
            connections = [
                stack.enter_context(limiter_engine.connect())
                for _ in range(POSTGRES_LIMITER_POOL_SIZE)
            ]
            for connection in connections:
                connection.execute(text("SELECT 1"))
                connection.execute(text("SELECT id FROM rate_limit_buckets WHERE false"))
                if connection.dialect.name == "postgresql":
                    permissions_ready = connection.execute(
                        text(
                            "SELECT "
                            "has_table_privilege(current_user, 'rate_limit_buckets', 'SELECT') "
                            "AND has_table_privilege(current_user, 'rate_limit_buckets', 'INSERT') "
                            "AND has_table_privilege(current_user, 'rate_limit_buckets', 'UPDATE') "
                            "AND has_table_privilege(current_user, 'rate_limit_buckets', 'DELETE') "
                            "AND has_sequence_privilege("
                            "current_user, pg_get_serial_sequence('rate_limit_buckets', 'id'), "
                            "'USAGE')"
                        )
                    ).scalar_one()
                    if permissions_ready is not True:
                        raise RateLimitUnavailable("durable rate limiter is unavailable")
    except RateLimitUnavailable:
        runtime.close()
        raise
    except SQLAlchemyError:
        runtime.close()
        raise RateLimitUnavailable("durable rate limiter is unavailable") from None
    return runtime


configure_engine()


def get_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def initialize_database() -> None:
    settings = get_settings()
    if settings.database_password is None and settings.database_url.startswith("sqlite:///"):
        from app.backup import assert_no_incomplete_restore

        database_path = Path(settings.database_url.removeprefix("sqlite:///"))
        assert_no_incomplete_restore(database_path.resolve().parent)
    # Import before migration so the current target metadata is registered.
    from app import models  # noqa: F401
    from app.migration_runner import upgrade_database

    upgrade_database(engine)
