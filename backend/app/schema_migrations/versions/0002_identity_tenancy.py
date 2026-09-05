"""Add the identity and organization ownership foundation.

Revision ID: 0002_identity
Revises: 0001_v080
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_identity"
down_revision: str | None = "0001_v080"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LOCAL_ORGANIZATION_ID = 1
LOCAL_USER_ID = 1
LOCAL_MEMBERSHIP_ID = 1


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _has_column(table: str, name: str) -> bool:
    return name in {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def _has_index(table: str, name: str) -> bool:
    return name in {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table)}


def _create_identity_tables() -> None:
    if not _has_table("organizations"):
        op.create_table(
            "organizations",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("slug", sa.String(63), nullable=False),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.UniqueConstraint("slug", name="uq_organizations_slug"),
        )
    if not _has_table("users"):
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("oidc_issuer", sa.String(500), nullable=False),
            sa.Column("oidc_subject", sa.String(255), nullable=False),
            sa.Column("email", sa.String(320), nullable=True),
            sa.Column("display_name", sa.String(120), nullable=False),
            sa.Column("status", sa.String(16), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.CheckConstraint("status IN ('active', 'disabled')", name="ck_users_status"),
            sa.UniqueConstraint("oidc_issuer", "oidc_subject", name="uq_user_identity"),
        )
    if not _has_table("memberships"):
        op.create_table(
            "memberships",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("organization_id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("role", sa.String(16), nullable=False),
            sa.Column("status", sa.String(16), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.CheckConstraint(
                "role IN ('owner', 'admin', 'operator', 'auditor', 'viewer')",
                name="ck_memberships_role",
            ),
            sa.CheckConstraint(
                "status IN ('active', 'disabled')", name="ck_memberships_status"
            ),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("organization_id", "user_id", name="uq_membership_identity"),
        )
        op.create_index("ix_memberships_organization_id", "memberships", ["organization_id"])
        op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    if not _has_table("browser_sessions"):
        op.create_table(
            "browser_sessions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("token_hash", sa.String(64), nullable=False),
            sa.Column("csrf_token_hash", sa.String(64), nullable=False),
            sa.Column("membership_id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["membership_id"], ["memberships.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("token_hash", name="uq_browser_sessions_token_hash"),
        )
        op.create_index(
            "ix_browser_sessions_membership_id", "browser_sessions", ["membership_id"]
        )
        op.create_index("ix_browser_sessions_expires_at", "browser_sessions", ["expires_at"])


def _seed_local_identity() -> None:
    connection = op.get_bind()
    organization = connection.execute(
        sa.text("SELECT id FROM organizations WHERE slug = :slug"), {"slug": "local"}
    ).scalar_one_or_none()
    if organization is None:
        organization = connection.execute(
            sa.text("INSERT INTO organizations (slug, name) VALUES (:slug, :name) RETURNING id"),
            {"slug": "local", "name": "Local RedDock"},
        ).scalar_one()
    if organization != LOCAL_ORGANIZATION_ID:
        raise RuntimeError("The reserved local organization ID is already inconsistent")

    user = connection.execute(
        sa.text(
            "SELECT id FROM users WHERE oidc_issuer = :issuer AND oidc_subject = :subject"
        ),
        {"issuer": "urn:reddock:local", "subject": "single-operator"},
    ).scalar_one_or_none()
    if user is None:
        user = connection.execute(
            sa.text(
                "INSERT INTO users "
                "(oidc_issuer, oidc_subject, display_name, status) "
                "VALUES (:issuer, :subject, :display_name, :status) RETURNING id"
            ),
            {
                "issuer": "urn:reddock:local",
                "subject": "single-operator",
                "display_name": "Local operator",
                "status": "active",
            },
        ).scalar_one()
    if user != LOCAL_USER_ID:
        raise RuntimeError("The reserved local user ID is already inconsistent")

    membership = connection.execute(
        sa.text(
            "SELECT id FROM memberships "
            "WHERE organization_id = :organization_id AND user_id = :user_id"
        ),
        {"organization_id": LOCAL_ORGANIZATION_ID, "user_id": LOCAL_USER_ID},
    ).scalar_one_or_none()
    if membership is None:
        membership = connection.execute(
            sa.text(
                "INSERT INTO memberships "
                "(organization_id, user_id, role, status) "
                "VALUES (:organization_id, :user_id, :role, :status) RETURNING id"
            ),
            {
                "organization_id": LOCAL_ORGANIZATION_ID,
                "user_id": LOCAL_USER_ID,
                "role": "owner",
                "status": "active",
            },
        ).scalar_one()
    if membership != LOCAL_MEMBERSHIP_ID:
        raise RuntimeError("The reserved local membership ID is already inconsistent")


def _own_existing_dockyards() -> None:
    if not _has_column("dockyards", "organization_id"):
        with op.batch_alter_table("dockyards") as batch:
            batch.add_column(
                sa.Column(
                    "organization_id",
                    sa.Integer(),
                    nullable=True,
                    server_default=sa.text(str(LOCAL_ORGANIZATION_ID)),
                )
            )
            batch.create_foreign_key(
                "fk_dockyards_organization_id",
                "organizations",
                ["organization_id"],
                ["id"],
                ondelete="RESTRICT",
            )
    statement = sa.text(
        "UPDATE dockyards SET organization_id = :id WHERE organization_id IS NULL"
    ).bindparams(id=LOCAL_ORGANIZATION_ID)
    op.execute(statement)
    nullable = next(
        column["nullable"]
        for column in sa.inspect(op.get_bind()).get_columns("dockyards")
        if column["name"] == "organization_id"
    )
    if nullable:
        with op.batch_alter_table("dockyards") as batch:
            batch.alter_column("organization_id", existing_type=sa.Integer(), nullable=False)
    if not _has_index("dockyards", "ix_dockyards_organization_id"):
        op.create_index("ix_dockyards_organization_id", "dockyards", ["organization_id"])


def upgrade() -> None:
    _create_identity_tables()
    _seed_local_identity()
    _own_existing_dockyards()


def downgrade() -> None:
    if _has_column("dockyards", "organization_id"):
        with op.batch_alter_table("dockyards") as batch:
            batch.drop_column("organization_id")
    for table in ("browser_sessions", "memberships", "users", "organizations"):
        if _has_table(table):
            op.drop_table(table)
