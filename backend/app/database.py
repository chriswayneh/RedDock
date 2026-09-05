from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def _connect_args(database_url: str) -> dict:
    if not database_url.startswith("sqlite"):
        return {}
    # Discovery runs write from a background thread, so the connection is shared
    # across threads and a short lock wait avoids spurious "database is locked".
    return {"check_same_thread": False, "timeout": 15}


engine: Engine
SessionLocal = sessionmaker(autoflush=False, autocommit=False)


def configure_engine() -> None:
    """(Re)build the engine from current settings and rebind the session maker."""
    global engine
    previous = globals().get("engine")
    if previous is not None:
        previous.dispose()
    url = get_settings().database_url
    engine = create_engine(url, connect_args=_connect_args(url))
    SessionLocal.configure(bind=engine)


configure_engine()


def get_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def initialize_database() -> None:
    # Import before migration so the current target metadata is registered.
    from app import models  # noqa: F401
    from app.migration_runner import upgrade_database

    upgrade_database(engine)
