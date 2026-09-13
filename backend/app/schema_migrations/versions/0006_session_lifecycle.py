"""Add secure browser-session lifecycle state.

Revision ID: 0006_session_lifecycle
Revises: 0005_rate_limits
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_session_lifecycle"
down_revision: str | None = "0005_rate_limits"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("browser_sessions") as batch:
        batch.add_column(sa.Column("family_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("generation", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("token_issued_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("replaced_at", sa.DateTime(timezone=True), nullable=True))

    op.execute(
        sa.text(
            "UPDATE browser_sessions "
            "SET created_at = last_seen_at "
            "WHERE created_at IS NULL OR created_at > last_seen_at"
        )
    )
    op.execute(
        sa.text(
            "UPDATE browser_sessions "
            "SET family_hash = token_hash, generation = 0, "
            "token_issued_at = last_seen_at"
        )
    )

    with op.batch_alter_table("browser_sessions") as batch:
        batch.alter_column(
            "created_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
        )
        batch.alter_column(
            "family_hash",
            existing_type=sa.String(64),
            nullable=False,
        )
        batch.alter_column(
            "generation",
            existing_type=sa.Integer(),
            nullable=False,
        )
        batch.alter_column(
            "token_issued_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
        )
        batch.create_check_constraint(
            "ck_browser_session_token_hash",
            "length(token_hash) = 64",
        )
        batch.create_check_constraint(
            "ck_browser_session_csrf_hash",
            "length(csrf_token_hash) = 64",
        )
        batch.create_check_constraint(
            "ck_browser_session_family_hash",
            "length(family_hash) = 64",
        )
        batch.create_check_constraint(
            "ck_browser_session_generation",
            "generation BETWEEN 0 AND 16",
        )
        batch.create_check_constraint(
            "ck_browser_session_created_before_token",
            "created_at <= token_issued_at",
        )
        batch.create_check_constraint(
            "ck_browser_session_token_before_seen",
            "token_issued_at <= last_seen_at",
        )
        batch.create_check_constraint(
            "ck_browser_session_seen_before_expiry",
            "last_seen_at < expires_at",
        )
        batch.create_unique_constraint(
            "uq_browser_session_family_generation",
            ["family_hash", "generation"],
        )

    op.create_index(
        "uq_browser_sessions_active_family",
        "browser_sessions",
        ["family_hash"],
        unique=True,
        sqlite_where=sa.text("replaced_at IS NULL AND revoked_at IS NULL"),
        postgresql_where=sa.text("replaced_at IS NULL AND revoked_at IS NULL"),
    )
    op.create_index(
        "ix_browser_sessions_last_seen",
        "browser_sessions",
        ["last_seen_at", "id"],
    )


def downgrade() -> None:
    # A pre-0006 reader has no replaced-at predicate. Persist retirement as
    # revocation before dropping rotation state so old bearer tokens stay dead.
    op.execute(
        sa.text(
            "UPDATE browser_sessions "
            "SET revoked_at = COALESCE(revoked_at, replaced_at) "
            "WHERE replaced_at IS NOT NULL"
        )
    )
    op.drop_index("ix_browser_sessions_last_seen", table_name="browser_sessions")
    op.drop_index("uq_browser_sessions_active_family", table_name="browser_sessions")
    with op.batch_alter_table("browser_sessions") as batch:
        batch.drop_constraint("uq_browser_session_family_generation", type_="unique")
        batch.drop_constraint("ck_browser_session_seen_before_expiry", type_="check")
        batch.drop_constraint("ck_browser_session_token_before_seen", type_="check")
        batch.drop_constraint("ck_browser_session_created_before_token", type_="check")
        batch.drop_constraint("ck_browser_session_generation", type_="check")
        batch.drop_constraint("ck_browser_session_family_hash", type_="check")
        batch.drop_constraint("ck_browser_session_csrf_hash", type_="check")
        batch.drop_constraint("ck_browser_session_token_hash", type_="check")
        batch.drop_column("replaced_at")
        batch.drop_column("token_issued_at")
        batch.drop_column("generation")
        batch.drop_column("family_hash")
        batch.alter_column(
            "created_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=True,
        )
