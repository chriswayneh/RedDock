"""Record the complete v0.8.0 schema as the migration baseline.

Revision ID: 0001_v080
Revises: None
"""

from collections.abc import Sequence

revision: str = "0001_v080"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The migration runner validates and stamps existing v0.8.0 databases.
    # Fresh databases are created from the current model and stamped at head.
    pass


def downgrade() -> None:
    # A baseline stamp never owns an operator's pre-existing data.
    pass
