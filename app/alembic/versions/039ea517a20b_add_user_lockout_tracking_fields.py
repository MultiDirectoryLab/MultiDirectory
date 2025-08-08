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
    with op.batch_alter_table("Users", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "failed_auth_attempts",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            if_not_exists=True,
        )

        batch_op.add_column(
            sa.Column(
                "last_failed_auth",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            if_not_exists=True,
        )

        batch_op.add_column(
            sa.Column(
                "is_auth_locked",
                sa.Boolean(),
                nullable=False,
                server_default="false",
            ),
            if_not_exists=True,
        )

    with op.batch_alter_table("PasswordPolicies", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "max_failed_attempts",
                sa.Integer(),
                nullable=False,
                server_default="6",
            ),
            if_not_exists=True,
        )

        batch_op.add_column(
            sa.Column(
                "failed_attempts_reset_sec",
                sa.Integer(),
                nullable=False,
                server_default="60",
            ),
            if_not_exists=True,
        )

        batch_op.add_column(
            sa.Column(
                "lockout_duration_sec",
                sa.Integer(),
                nullable=False,
                server_default="600",
            ),
            if_not_exists=True,
        )

        batch_op.add_column(
            sa.Column(
                "fail_delay_sec",
                sa.Integer(),
                nullable=False,
                server_default="5",
            ),
            if_not_exists=True,
        )


def downgrade() -> None:
    """Downgrade."""
    with op.batch_alter_table("PasswordPolicies", schema=None) as batch_op:
        batch_op.drop_column("fail_delay_sec", if_exists=True)
        batch_op.drop_column("lockout_duration_sec", if_exists=True)
        batch_op.drop_column("failed_attempts_reset_sec", if_exists=True)
        batch_op.drop_column("max_failed_attempts", if_exists=True)

    with op.batch_alter_table("Users", schema=None) as batch_op:
        batch_op.drop_column("is_auth_locked", if_exists=True)
        batch_op.drop_column("last_failed_auth", if_exists=True)
        batch_op.drop_column("failed_auth_attempts", if_exists=True)
