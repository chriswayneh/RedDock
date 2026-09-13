from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.config import DormantServerRuntimeConfig, get_settings
from app.orm import Base as Base

POSTGRES_APPLICATION_POOL_SIZE = 5
POSTGRES_APPLICATION_MAX_OVERFLOW = 10
POSTGRES_APPLICATION_POOL_TIMEOUT_SECONDS = 5
POSTGRES_SERVER_STATEMENT_TIMEOUT_MS = 120_000
POSTGRES_SERVER_LOCK_TIMEOUT_MS = 5_000
POSTGRES_SERVER_IDLE_TRANSACTION_TIMEOUT_MS = 660_000
POSTGRES_SERVER_TRANSACTION_TIMEOUT_MS = 900_000
POSTGRES_SERVER_STARTUP_LOCK_TIMEOUT_MS = 120_000
POSTGRES_LIMITER_POOL_SIZE = 2
POSTGRES_LIMITER_POOL_TIMEOUT_SECONDS = 2
POSTGRES_CONNECT_TIMEOUT_SECONDS = 5
POSTGRES_LIMITER_STATEMENT_TIMEOUT_MS = 2_000
POSTGRES_LIMITER_LOCK_TIMEOUT_MS = 1_000


def _limiter_privileges_are_exact(
    connection: Connection,
    *,
    expected_role: str,
    expected_database: str,
    expected_connections: int,
) -> bool:
    """Verify the effective PostgreSQL identity, required access, and exclusions."""

    if connection.dialect.name != "postgresql":
        return True
    statement = text(
        """
        SELECT
            current_user = :expected_role
            AND session_user = :expected_role
            AND current_database() = :expected_database
            AND role.rolcanlogin
            AND NOT role.rolinherit
            AND NOT role.rolsuper
            AND NOT role.rolcreatedb
            AND NOT role.rolcreaterole
            AND NOT role.rolreplication
            AND NOT role.rolbypassrls
            AND role.rolconfig IS NULL
            AND role.rolconnlimit = :expected_connections
            AND NOT EXISTS (
                SELECT 1 FROM pg_auth_members membership
                WHERE membership.member = role.oid
            )
            AND has_database_privilege(current_user, current_database(), 'CONNECT')
            AND NOT has_database_privilege(current_user, current_database(), 'CREATE')
            AND NOT has_database_privilege(current_user, current_database(), 'TEMPORARY')
            AND NOT has_database_privilege(
                current_user, current_database(), 'CONNECT WITH GRANT OPTION'
            )
            AND database.datdba <> role.oid
            AND NOT EXISTS (
                SELECT 1
                FROM pg_database other_database
                WHERE other_database.datname <> current_database()
                  AND (
                      other_database.datdba = role.oid
                      OR has_database_privilege(current_user, other_database.oid, 'CREATE')
                      OR (
                          other_database.datallowconn
                          AND (
                              has_database_privilege(
                                  current_user, other_database.oid, 'CONNECT'
                              )
                              OR has_database_privilege(
                                  current_user, other_database.oid, 'TEMPORARY'
                              )
                          )
                      )
                  )
            )
            AND has_schema_privilege(current_user, 'public', 'USAGE')
            AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
            AND NOT has_schema_privilege(current_user, 'public', 'USAGE WITH GRANT OPTION')
            AND namespace.nspowner <> role.oid
            AND has_table_privilege(current_user, 'public.rate_limit_buckets', 'SELECT')
            AND has_table_privilege(current_user, 'public.rate_limit_buckets', 'INSERT')
            AND has_table_privilege(current_user, 'public.rate_limit_buckets', 'UPDATE')
            AND has_table_privilege(current_user, 'public.rate_limit_buckets', 'DELETE')
            AND NOT has_table_privilege(current_user, 'public.rate_limit_buckets', 'TRUNCATE')
            AND NOT has_table_privilege(current_user, 'public.rate_limit_buckets', 'REFERENCES')
            AND NOT has_table_privilege(current_user, 'public.rate_limit_buckets', 'TRIGGER')
            AND NOT has_table_privilege(current_user, 'public.rate_limit_buckets', 'MAINTAIN')
            AND NOT has_table_privilege(
                current_user, 'public.rate_limit_buckets', 'SELECT WITH GRANT OPTION'
            )
            AND NOT has_table_privilege(
                current_user, 'public.rate_limit_buckets', 'INSERT WITH GRANT OPTION'
            )
            AND NOT has_table_privilege(
                current_user, 'public.rate_limit_buckets', 'UPDATE WITH GRANT OPTION'
            )
            AND NOT has_table_privilege(
                current_user, 'public.rate_limit_buckets', 'DELETE WITH GRANT OPTION'
            )
            AND NOT has_any_column_privilege(
                current_user, 'public.rate_limit_buckets', 'SELECT WITH GRANT OPTION'
            )
            AND NOT has_any_column_privilege(
                current_user, 'public.rate_limit_buckets', 'INSERT WITH GRANT OPTION'
            )
            AND NOT has_any_column_privilege(
                current_user, 'public.rate_limit_buckets', 'UPDATE WITH GRANT OPTION'
            )
            AND NOT has_any_column_privilege(
                current_user, 'public.rate_limit_buckets', 'REFERENCES WITH GRANT OPTION'
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_attribute attribute
                WHERE attribute.attrelid = bucket.oid
                  AND attribute.attacl IS NOT NULL
            )
            AND bucket.relowner <> role.oid
            AND NOT bucket.relrowsecurity
            AND NOT bucket.relforcerowsecurity
            AND NOT EXISTS (
                SELECT 1
                FROM pg_trigger bucket_trigger
                WHERE bucket_trigger.tgrelid = bucket.oid
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_constraint relationship
                WHERE relationship.contype = 'f'
                  AND (
                      relationship.conrelid = bucket.oid
                      OR relationship.confrelid = bucket.oid
                  )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_rewrite rewrite
                WHERE rewrite.ev_class = bucket.oid
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_inherits inheritance
                WHERE inheritance.inhrelid = bucket.oid
                   OR inheritance.inhparent = bucket.oid
            )
            AND has_sequence_privilege(
                current_user, 'public.rate_limit_buckets_id_seq', 'USAGE'
            )
            AND NOT has_sequence_privilege(
                current_user, 'public.rate_limit_buckets_id_seq', 'SELECT'
            )
            AND NOT has_sequence_privilege(
                current_user, 'public.rate_limit_buckets_id_seq', 'UPDATE'
            )
            AND NOT has_sequence_privilege(
                current_user,
                'public.rate_limit_buckets_id_seq',
                'USAGE WITH GRANT OPTION'
            )
            AND sequence.relowner <> role.oid
            AND NOT EXISTS (
                SELECT 1
                FROM pg_class object
                JOIN pg_namespace object_namespace
                    ON object_namespace.oid = object.relnamespace
                WHERE object_namespace.nspname NOT LIKE 'pg_%'
                  AND object_namespace.nspname <> 'information_schema'
                  AND object.oid NOT IN (bucket.oid, sequence.oid)
                  AND (
                      object.relowner = role.oid
                      OR (
                          object.relkind IN ('r', 'p', 'v', 'm', 'f')
                          AND (
                              has_table_privilege(current_user, object.oid, 'SELECT')
                              OR has_table_privilege(current_user, object.oid, 'INSERT')
                              OR has_table_privilege(current_user, object.oid, 'UPDATE')
                              OR has_table_privilege(current_user, object.oid, 'DELETE')
                              OR has_table_privilege(current_user, object.oid, 'TRUNCATE')
                              OR has_table_privilege(current_user, object.oid, 'REFERENCES')
                              OR has_table_privilege(current_user, object.oid, 'TRIGGER')
                              OR has_table_privilege(current_user, object.oid, 'MAINTAIN')
                              OR has_any_column_privilege(current_user, object.oid, 'SELECT')
                              OR has_any_column_privilege(current_user, object.oid, 'INSERT')
                              OR has_any_column_privilege(current_user, object.oid, 'UPDATE')
                              OR has_any_column_privilege(current_user, object.oid, 'REFERENCES')
                          )
                      )
                      OR (
                          object.relkind = 'S'
                          AND (
                              has_sequence_privilege(current_user, object.oid, 'USAGE')
                              OR has_sequence_privilege(current_user, object.oid, 'SELECT')
                              OR has_sequence_privilege(current_user, object.oid, 'UPDATE')
                          )
                      )
                  )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_namespace other_namespace
                WHERE other_namespace.nspname NOT LIKE 'pg_%'
                  AND other_namespace.nspname NOT IN ('information_schema', 'public')
                  AND (
                      other_namespace.nspowner = role.oid
                      OR has_schema_privilege(current_user, other_namespace.oid, 'USAGE')
                      OR has_schema_privilege(current_user, other_namespace.oid, 'CREATE')
                   )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_type owned_type
                WHERE owned_type.typowner = role.oid
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_proc routine
                JOIN pg_namespace routine_namespace
                    ON routine_namespace.oid = routine.pronamespace
                WHERE routine_namespace.nspname NOT LIKE 'pg_%'
                  AND routine_namespace.nspname <> 'information_schema'
                  AND (
                      routine.proowner = role.oid
                      OR has_function_privilege(current_user, routine.oid, 'EXECUTE')
                  )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_largeobject_metadata large_object
                WHERE large_object.lomowner = role.oid
                   OR EXISTS (
                       SELECT 1
                       FROM aclexplode(large_object.lomacl) access
                       WHERE access.grantee IN (0, role.oid)
                         AND access.privilege_type IN ('SELECT', 'UPDATE')
                   )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_parameter_acl parameter
                WHERE has_parameter_privilege(current_user, parameter.parname, 'SET')
                   OR has_parameter_privilege(
                       current_user, parameter.parname, 'ALTER SYSTEM'
                   )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_tablespace tablespace
                WHERE tablespace.spcowner = role.oid
                   OR has_tablespace_privilege(
                       current_user, tablespace.oid, 'CREATE'
                   )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_foreign_data_wrapper wrapper
                WHERE wrapper.fdwowner = role.oid
                   OR has_foreign_data_wrapper_privilege(
                       current_user, wrapper.oid, 'USAGE'
                   )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_foreign_server server
                WHERE server.srvowner = role.oid
                   OR has_server_privilege(current_user, server.oid, 'USAGE')
            )
        FROM pg_roles role
        JOIN pg_database database ON database.datname = current_database()
        JOIN pg_namespace namespace ON namespace.nspname = 'public'
        JOIN pg_class bucket ON bucket.oid = 'public.rate_limit_buckets'::regclass
        JOIN pg_class sequence
            ON sequence.oid = 'public.rate_limit_buckets_id_seq'::regclass
        WHERE role.rolname = current_user
        """
    )
    return (
        connection.execute(
            statement,
            {
                "expected_role": expected_role,
                "expected_database": expected_database,
                "expected_connections": expected_connections,
            },
        ).scalar_one()
        is True
    )


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


class PrimaryDatabaseUnavailable(RuntimeError):
    """The future server database capability could not start safely."""

    def __init__(self) -> None:
        super().__init__("primary database runtime is unavailable")


def _server_database_url(config: DormantServerRuntimeConfig) -> URL:
    return URL.create(
        "postgresql+psycopg",
        username=config.database_user,
        password=config.database_password.get_secret_value(),
        host=config.database_host,
        port=config.database_port,
        database=config.database_name,
    )


def _server_application_engine(config: DormantServerRuntimeConfig) -> Engine:
    """Build only from the validated component configuration, never ambient settings."""

    return create_engine(
        _server_database_url(config),
        pool_size=POSTGRES_APPLICATION_POOL_SIZE,
        max_overflow=POSTGRES_APPLICATION_MAX_OVERFLOW,
        pool_timeout=POSTGRES_APPLICATION_POOL_TIMEOUT_SECONDS,
        pool_pre_ping=True,
        isolation_level="READ COMMITTED",
        execution_options={"schema_translate_map": {None: "public"}},
        connect_args={
            "connect_timeout": POSTGRES_CONNECT_TIMEOUT_SECONDS,
            "application_name": "reddock-server-main",
            "options": (
                f"-c statement_timeout={POSTGRES_SERVER_STATEMENT_TIMEOUT_MS} "
                f"-c lock_timeout={POSTGRES_SERVER_LOCK_TIMEOUT_MS} "
                "-c idle_in_transaction_session_timeout="
                f"{POSTGRES_SERVER_IDLE_TRANSACTION_TIMEOUT_MS} "
                f"-c transaction_timeout={POSTGRES_SERVER_TRANSACTION_TIMEOUT_MS} "
                "-c search_path=pg_catalog,public"
            ),
        },
    )


def _primary_connection_is_exact(
    connection: Connection,
    *,
    expected_user: str,
    expected_database: str,
) -> bool:
    if connection.dialect.name != "postgresql":
        return False
    return (
        connection.execute(
            text(
                """
                SELECT
                    current_user = :expected_user
                    AND session_user = :expected_user
                    AND current_database() = :expected_database
                    AND current_setting('application_name') = 'reddock-server-main'
                    AND current_setting('search_path') = 'pg_catalog,public'
                    AND current_setting('statement_timeout')::interval =
                        make_interval(secs => :statement_ms / 1000.0)
                    AND current_setting('lock_timeout')::interval =
                        make_interval(secs => :lock_ms / 1000.0)
                    AND current_setting('idle_in_transaction_session_timeout')::interval =
                        make_interval(secs => :idle_ms / 1000.0)
                    AND current_setting('transaction_timeout')::interval =
                        make_interval(secs => :transaction_ms / 1000.0)
                """
            ),
            {
                "expected_user": expected_user,
                "expected_database": expected_database,
                "statement_ms": POSTGRES_SERVER_STATEMENT_TIMEOUT_MS,
                "lock_ms": POSTGRES_SERVER_LOCK_TIMEOUT_MS,
                "idle_ms": POSTGRES_SERVER_IDLE_TRANSACTION_TIMEOUT_MS,
                "transaction_ms": POSTGRES_SERVER_TRANSACTION_TIMEOUT_MS,
            },
        ).scalar_one()
        is True
    )


class PrimaryDatabaseRuntime:
    """Own the future server's exact-config primary engine and session factory."""

    def __init__(self, config: DormantServerRuntimeConfig, engine: Engine) -> None:
        if not isinstance(config, DormantServerRuntimeConfig) or not isinstance(engine, Engine):
            raise ValueError("validated server configuration and owned engine are required")
        self.__engine = engine
        self.__sessions = sessionmaker(
            bind=engine,
            autoflush=False,
            autocommit=False,
        )
        self.__expected_user = config.database_user
        self.__expected_database = config.database_name
        self.__ready = False
        self.__closed = False

    def __repr__(self) -> str:
        return (
            "PrimaryDatabaseRuntime("
            f"ready={self.__ready}, closed={self.__closed})"
        )

    def _ensure_open(self) -> None:
        if self.__closed:
            raise PrimaryDatabaseUnavailable()

    def attest(self) -> None:
        """Prove the effective database identity and fixed session policy."""

        self._ensure_open()
        try:
            with self.__engine.connect() as connection:
                if not _primary_connection_is_exact(
                    connection,
                    expected_user=self.__expected_user,
                    expected_database=self.__expected_database,
                ):
                    raise PrimaryDatabaseUnavailable()
        except PrimaryDatabaseUnavailable:
            raise
        except SQLAlchemyError:
            raise PrimaryDatabaseUnavailable() from None

    @contextmanager
    def startup_session(self) -> Iterator[Session]:
        """Serialize migration and recovery, yielding one runtime-bound session."""

        self._ensure_open()
        if self.__ready:
            raise PrimaryDatabaseUnavailable()
        try:
            from app.migration_runner import upgrade_database_connection

            with self.__engine.connect() as connection:
                if not _primary_connection_is_exact(
                    connection,
                    expected_user=self.__expected_user,
                    expected_database=self.__expected_database,
                ):
                    raise PrimaryDatabaseUnavailable()
                connection.commit()
                lock_acquired = False
                acquisition_uncertain = False
                try:
                    connection.execute(
                        text("SELECT set_config('lock_timeout', :timeout, true)"),
                        {"timeout": f"{POSTGRES_SERVER_STARTUP_LOCK_TIMEOUT_MS}ms"},
                    )
                    acquisition_uncertain = True
                    connection.execute(
                        text("SELECT pg_advisory_lock(1919247471, 1937011316)")
                    ).scalar_one_or_none()
                    lock_acquired = True
                    acquisition_uncertain = False
                    connection.commit()
                    with connection.begin():
                        upgrade_database_connection(connection)
                    with Session(bind=connection) as session:
                        yield session
                finally:
                    cleanup_failed = acquisition_uncertain
                    try:
                        if connection.in_transaction():
                            connection.rollback()
                    except SQLAlchemyError:
                        cleanup_failed = True
                    if lock_acquired and not cleanup_failed:
                        try:
                            unlocked = connection.execute(
                                text("SELECT pg_advisory_unlock(1919247471, 1937011316)")
                            ).scalar_one()
                            if unlocked is not True:
                                cleanup_failed = True
                            else:
                                connection.commit()
                        except SQLAlchemyError:
                            cleanup_failed = True
                    if cleanup_failed:
                        try:
                            connection.invalidate()
                        except SQLAlchemyError:
                            pass
                        raise PrimaryDatabaseUnavailable()
                self.__ready = True
        except Exception:
            raise PrimaryDatabaseUnavailable() from None

    @property
    def engine(self) -> Engine:
        self._ensure_open()
        if not self.__ready:
            raise PrimaryDatabaseUnavailable()
        return self.__engine

    def session(self) -> Session:
        self._ensure_open()
        if not self.__ready:
            raise PrimaryDatabaseUnavailable()
        return self.__sessions()

    def close(self) -> None:
        if self.__closed:
            return
        self.__closed = True
        self.__ready = False
        self.__engine.dispose()


def create_server_primary_database_runtime(
    config: DormantServerRuntimeConfig,
) -> PrimaryDatabaseRuntime:
    """Create and attest one exact-config future server database capability."""

    if not isinstance(config, DormantServerRuntimeConfig):
        raise ValueError("validated dormant server runtime configuration is required")
    engine = None
    runtime = None
    try:
        engine = _server_application_engine(config)
        runtime = PrimaryDatabaseRuntime(config, engine)
        runtime.attest()
        return runtime
    except (PrimaryDatabaseUnavailable, SQLAlchemyError):
        try:
            if runtime is not None:
                runtime.close()
            elif engine is not None:
                engine.dispose()
        except Exception:
            pass
        raise PrimaryDatabaseUnavailable() from None


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
        username=config.rate_limit_database_user,
        password=config.rate_limit_database_password.get_secret_value(),
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
            execution_options={"schema_translate_map": {None: "public"}},
            connect_args={
                "connect_timeout": POSTGRES_CONNECT_TIMEOUT_SECONDS,
                "application_name": "reddock-limiter",
                "options": (
                    f"-c statement_timeout={POSTGRES_LIMITER_STATEMENT_TIMEOUT_MS} "
                    f"-c lock_timeout={POSTGRES_LIMITER_LOCK_TIMEOUT_MS} "
                    "-c search_path=pg_catalog,public"
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
                bucket_table = (
                    "public.rate_limit_buckets"
                    if connection.dialect.name == "postgresql"
                    else "rate_limit_buckets"
                )
                connection.execute(
                    text(f"SELECT id FROM {bucket_table} WHERE false")
                )
                if not _limiter_privileges_are_exact(
                    connection,
                    expected_role=config.rate_limit_database_user,
                    expected_database=config.database_name,
                    expected_connections=(
                        POSTGRES_LIMITER_POOL_SIZE * config.server_workers
                    ),
                ):
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
