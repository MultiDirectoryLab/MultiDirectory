"""Rename PasswordPolicies columns and create PasswordBanWords table.

Revision ID: a8b9fd2f2075
Revises: e4d6d99d32bd
Create Date: 2025-08-12 12:36:41.368759

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "a8b9fd2f2075"
down_revision = "e4d6d99d32bd"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.alter_column(
        "PasswordPolicies",
        "password_history_length",
        new_column_name="history_length",
    )
    op.alter_column(
        "PasswordPolicies",
        "maximum_password_age_days",
        new_column_name="max_age_days",
    )
    op.alter_column(
        "PasswordPolicies",
        "minimum_password_age_days",
        new_column_name="min_age_days",
    )
    op.alter_column(
        "PasswordPolicies",
        "minimum_password_length",
        new_column_name="min_length",
    )


def downgrade() -> None:
    """Downgrade."""
    op.alter_column(
        "PasswordPolicies",
        "history_length",
        new_column_name="password_history_length",
    )
    op.alter_column(
        "PasswordPolicies",
        "max_age_days",
        new_column_name="maximum_password_age_days",
    )
    op.alter_column(
        "PasswordPolicies",
        "min_age_days",
        new_column_name="minimum_password_age_days",
    )
    op.alter_column(
        "PasswordPolicies",
        "min_length",
        new_column_name="minimum_password_length",
    )
