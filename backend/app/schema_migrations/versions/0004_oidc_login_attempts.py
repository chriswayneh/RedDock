"""Add one-use OIDC authorization-code transactions.

Revision ID: 0004_oidc_attempts
Revises: 0003_security_audit
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_oidc_attempts"
down_revision: str | None = "0003_security_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("oidc_login_attempts"):
        return
    op.create_table(
        "oidc_login_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("browser_token_hash", sa.String(64), nullable=False),
        sa.Column("nonce_hash", sa.String(64), nullable=False),
        sa.Column("pkce_verifier", sa.String(128), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(state_hash) = 64", name="ck_oidc_attempt_state_hash"),
        sa.CheckConstraint(
            "length(browser_token_hash) = 64", name="ck_oidc_attempt_browser_token_hash"
        ),
        sa.CheckConstraint("length(nonce_hash) = 64", name="ck_oidc_attempt_nonce_hash"),
        sa.CheckConstraint(
            "length(pkce_verifier) BETWEEN 43 AND 128", name="ck_oidc_attempt_pkce_verifier"
        ),
        sa.UniqueConstraint("state_hash", name="uq_oidc_attempt_state_hash"),
        sa.UniqueConstraint(
            "browser_token_hash", name="uq_oidc_attempt_browser_token_hash"
        ),
    )
    op.create_index(
        "ix_oidc_login_attempts_expires_at", "oidc_login_attempts", ["expires_at"]
    )


def downgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("oidc_login_attempts"):
        op.drop_table("oidc_login_attempts")
