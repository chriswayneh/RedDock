"""Add tenant-bound security audit events.

Revision ID: 0003_security_audit
Revises: 0002_identity
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_security_audit"
down_revision: str | None = "0002_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("security_audit_events"):
        return
    op.create_table(
        "security_audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_membership_id", sa.Integer(), nullable=True),
        sa.Column("actor_role", sa.String(16), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=True),
        sa.Column("target_id", sa.String(64), nullable=True),
        sa.Column("reason_code", sa.String(64), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint(
            "outcome IN ('success', 'denied', 'failure')",
            name="ck_security_audit_events_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["actor_membership_id"], ["memberships.id"], ondelete="SET NULL"
        ),
    )
    op.create_index(
        "ix_security_audit_org_time",
        "security_audit_events",
        ["organization_id", "created_at"],
    )


def downgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("security_audit_events"):
        op.drop_table("security_audit_events")
