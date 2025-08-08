"""extend_password_policy_enterprise.

Revision ID: 5d413a7fa211
Revises: 05ddc0bd562a
Create Date: 2025-08-08 09:39:00.142964

"""

import sqlalchemy as sa
from alembic import op

revision = "5d413a7fa211"
down_revision = "05ddc0bd562a"
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

    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_length",
            sa.Integer(),
            nullable=False,
            server_default="32",
        ),
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "language",
            sa.String(),
            nullable=False,
            server_default="Latin",
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "is_exact_match",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_lowercase_letters_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_uppercase_letters_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_special_symbols_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_unique_symbols_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_repeating_symbols_in_row_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_digits_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_sequential_keyboard_symbols_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_sequential_alphabet_symbols_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.create_table(
        "PasswordBanWords",
        sa.Column("word", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("word"),
    )

    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.create_index(
        "idx_password_ban_words_word_gin_trgm",
        "PasswordBanWords",
        ["word"],
        postgresql_using="gin",
        postgresql_ops={"word": "gin_trgm_ops"},
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_index(
        "idx_password_ban_words_word_gin_trgm",
        table_name="PasswordBanWords",
    )
    op.drop_table("PasswordBanWords")

    op.drop_column("PasswordPolicies", "max_sequential_alphabet_symbols_count")
    op.drop_column("PasswordPolicies", "max_sequential_keyboard_symbols_count")
    op.drop_column("PasswordPolicies", "min_digits_count")
    op.drop_column("PasswordPolicies", "max_repeating_symbols_in_row_count")
    op.drop_column("PasswordPolicies", "min_unique_symbols_count")
    op.drop_column("PasswordPolicies", "min_special_symbols_count")
    op.drop_column("PasswordPolicies", "min_uppercase_letters_count")
    op.drop_column("PasswordPolicies", "min_lowercase_letters_count")
    op.drop_column("PasswordPolicies", "is_exact_match")
    op.drop_column("PasswordPolicies", "language")
    op.drop_column("PasswordPolicies", "max_length")

    op.alter_column(
        "PasswordPolicies",
        "min_length",
        new_column_name="minimum_password_length",
    )
    op.alter_column(
        "PasswordPolicies",
        "min_age_days",
        new_column_name="minimum_password_age_days",
    )
    op.alter_column(
        "PasswordPolicies",
        "max_age_days",
        new_column_name="maximum_password_age_days",
    )
    op.alter_column(
        "PasswordPolicies",
        "history_length",
        new_column_name="password_history_length",
    )
