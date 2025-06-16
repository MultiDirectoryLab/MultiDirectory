"""Extend Password Policy.

Revision ID: ed84fda9c642
Revises: ba78cef9700a
Create Date: 2025-06-10 15:04:23.633100

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "ed84fda9c642"
down_revision = "ba78cef9700a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.drop_column(
        "PasswordPolicies",
        "password_must_meet_complexity_requirements",
    )


def downgrade() -> None:
    """Downgrade."""
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "password_must_meet_complexity_requirements",
            sa.BOOLEAN(),
            server_default=sa.text("true"),
            autoincrement=False,
            nullable=False,
        ),
    )
