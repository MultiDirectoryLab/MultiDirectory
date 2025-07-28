"""empty message.

Revision ID: 52803ca42e35
Revises: 35d1542d2505
Create Date: 2025-07-24 08:57:15.264973

"""

import sqlalchemy as sa
from alembic import op

revision = "52803ca42e35"
down_revision = "196f0d327c6a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.add_column(
        "Users",
        sa.Column(
            "failedAuthAttempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "Users",
        sa.Column("lastFailedAuth", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_column("Users", "lastFailedAuth")
    op.drop_column("Users", "failedAuthAttempts")
