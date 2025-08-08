"""add_user_lockout_tracking_fields.

Revision ID: 039ea517a20b
Revises: 5d413a7fa211
Create Date: 2025-08-08 09:46:11.861691

"""

import sqlalchemy as sa
from alembic import op

revision = "039ea517a20b"
down_revision = "5d413a7fa211"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.add_column(
        "Users",
        sa.Column(
            "failed_auth_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "Users",
        sa.Column(
            "last_failed_auth",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "Users",
        sa.Column(
            "is_auth_locked",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_failed_attempts",
            sa.Integer(),
            nullable=False,
            server_default="6",
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "failed_attempts_reset_sec",
            sa.Integer(),
            nullable=False,
            server_default="60",
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "lockout_duration_sec",
            sa.Integer(),
            nullable=False,
            server_default="600",
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "fail_delay_sec",
            sa.Integer(),
            nullable=False,
            server_default="5",
        ),
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_column("PasswordPolicies", "fail_delay_sec")
    op.drop_column("PasswordPolicies", "lockout_duration_sec")
    op.drop_column("PasswordPolicies", "failed_attempts_reset_sec")
    op.drop_column("PasswordPolicies", "max_failed_attempts")

    op.drop_column("Users", "is_auth_locked")
    op.drop_column("Users", "last_failed_auth")
    op.drop_column("Users", "failed_auth_attempts")
