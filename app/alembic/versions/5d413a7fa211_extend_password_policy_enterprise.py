"""extend_password_policy_enterprise.

Revision ID: 5d413a7fa211
Revises: 05ddc0bd562a
Create Date: 2025-08-08 09:39:00.142964

"""

import sqlalchemy as sa
from alembic import op

revision = "5d413a7fa211"
down_revision = "e4d6d99d32bd"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    with op.batch_alter_table("PasswordPolicies", schema=None) as batch_op:
        batch_op.alter_column(
            "password_history_length",
            new_column_name="history_length",
        )
        batch_op.alter_column(
            "maximum_password_age_days",
            new_column_name="max_age_days",
        )
        batch_op.alter_column(
            "minimum_password_age_days",
            new_column_name="min_age_days",
        )
        batch_op.alter_column(
            "minimum_password_length",
            new_column_name="min_length",
        )

        batch_op.add_column(
            sa.Column(
                "max_length",
                sa.Integer(),
                nullable=False,
                server_default="32",
            ),
        )

        batch_op.add_column(
            sa.Column(
                "language",
                sa.String(),
                nullable=False,
                server_default="Latin",
            ),
        )

        batch_op.add_column(
            sa.Column(
                "is_exact_match",
                sa.Boolean(),
                nullable=False,
                server_default="false",
            ),
        )

        batch_op.add_column(
            sa.Column(
                "min_lowercase_letters_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )

        batch_op.add_column(
            sa.Column(
                "min_uppercase_letters_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )

        batch_op.add_column(
            sa.Column(
                "min_special_symbols_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )

        batch_op.add_column(
            sa.Column(
                "min_unique_symbols_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )

        batch_op.add_column(
            sa.Column(
                "max_repeating_symbols_in_row_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )

        batch_op.add_column(
            sa.Column(
                "min_digits_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )

        batch_op.add_column(
            sa.Column(
                "max_sequential_keyboard_symbols_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )

        batch_op.add_column(
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

    with op.batch_alter_table("PasswordPolicies", schema=None) as batch_op:
        batch_op.drop_column(
            "max_sequential_alphabet_symbols_count",
        )
        batch_op.drop_column(
            "max_sequential_keyboard_symbols_count",
        )
        batch_op.drop_column("min_digits_count")
        batch_op.drop_column(
            "max_repeating_symbols_in_row_count",
        )
        batch_op.drop_column("min_unique_symbols_count")
        batch_op.drop_column("min_special_symbols_count")
        batch_op.drop_column("min_uppercase_letters_count")
        batch_op.drop_column("min_lowercase_letters_count")
        batch_op.drop_column("is_exact_match")
        batch_op.drop_column("language")
        batch_op.drop_column("max_length")

        batch_op.alter_column(
            "min_length",
            new_column_name="minimum_password_length",
        )
        batch_op.alter_column(
            "min_age_days",
            new_column_name="minimum_password_age_days",
        )
        batch_op.alter_column(
            "max_age_days",
            new_column_name="maximum_password_age_days",
        )
        batch_op.alter_column(
            "history_length",
            new_column_name="password_history_length",
        )
