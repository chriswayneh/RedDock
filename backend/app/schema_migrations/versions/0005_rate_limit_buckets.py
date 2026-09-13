"""Add cross-worker authentication rate-limit buckets.

Revision ID: 0005_rate_limits
Revises: 0004_oidc_attempts
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_rate_limits"
down_revision: str | None = "0004_oidc_attempts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("rate_limit_buckets"):
        raise RuntimeError(
            "Unexpected preexisting rate_limit_buckets table; manual database review is required"
        )
    op.create_table(
        "rate_limit_buckets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "action IN ('oidc.login', 'oidc.callback', 'request.mutation')",
            name="ck_rate_limit_action",
        ),
        sa.CheckConstraint("length(key_hash) = 64", name="ck_rate_limit_key_hash"),
        sa.CheckConstraint(
            "attempt_count BETWEEN 1 AND 1000000", name="ck_rate_limit_attempt_count"
        ),
        sa.UniqueConstraint("action", "key_hash", name="uq_rate_limit_bucket"),
    )
    op.create_index("ix_rate_limit_expiry", "rate_limit_buckets", ["expires_at", "id"])


def downgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("rate_limit_buckets"):
        op.drop_table("rate_limit_buckets")
