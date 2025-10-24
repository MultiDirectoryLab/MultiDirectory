"""Extend Password Policy by priority and group membership.

Revision ID: ad52bc16b87d
Revises: 93ba193c6a53
Create Date: 2025-10-20 12:57:49.157153

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: None | str = "ad52bc16b87d"
down_revision: None | str = "93ba193c6a53"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade() -> None:
    """Upgrade."""
    op.create_index(
        op.f("idx_password_policies_name"),
        "PasswordPolicies",
        ["name"],
        postgresql_using="hash",
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "priority",
            sa.Integer(),
            nullable=False,
            unique=True,
        ),
    )

    op.alter_column(
        "PasswordPolicies",
        "password_history_length",
        server_default=None,
    )
    op.alter_column(
        "PasswordPolicies",
        "maximum_password_age_days",
        server_default=None,
    )
    op.alter_column(
        "PasswordPolicies",
        "minimum_password_age_days",
        server_default=None,
    )
    op.alter_column(
        "PasswordPolicies",
        "minimum_password_length",
        server_default=None,
    )
    op.alter_column(
        "PasswordPolicies",
        "password_must_meet_complexity_requirements",
        server_default=None,
    )

    op.create_table(
        "GroupPasswordPolicyMemberships",
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("password_policy_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["Groups.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["password_policy_id"],
            ["PasswordPolicies.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("group_id", "password_policy_id"),
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_table("GroupPasswordPolicyMemberships")

    op.alter_column(
        "PasswordPolicies",
        "password_must_meet_complexity_requirements",
        server_default=sa.text("false"),
    )
    op.alter_column(
        "PasswordPolicies",
        "minimum_password_length",
        server_default="7",
    )
    op.alter_column(
        "PasswordPolicies",
        "minimum_password_age_days",
        server_default="0",
    )
    op.alter_column(
        "PasswordPolicies",
        "maximum_password_age_days",
        server_default="0",
    )
    op.alter_column(
        "PasswordPolicies",
        "password_history_length",
        server_default="4",
    )

    op.drop_column("PasswordPolicies", "priority")

    op.drop_index(
        op.f("idx_password_policies_name"),
        table_name="PasswordPolicies",
    )
