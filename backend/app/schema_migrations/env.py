from alembic import context

from app.database import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    raise RuntimeError("RedDock migrations require a live database connection")


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is None:
        raise RuntimeError("RedDock migration runner did not provide a database connection")
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
