"""Initial audit.

Revision ID: f93261de37ad
Revises:
Create Date: 2025-04-17 07:43:18.525082

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "f93261de37ad"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column(
            "content", postgresql.JSON(astext_type=sa.Text()), nullable=False
        ),
        sa.Column(
            "server_delivery_status",
            postgresql.JSON(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("first_failed_at", sa.DateTime(), nullable=True),
        sa.Column(
            "retry_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_table("audit_log")
