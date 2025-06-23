"""Extend Password Policy.

Revision ID: ed84fda9c642
Revises: ba78cef9700a
Create Date: 2025-06-10 15:04:23.633100

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.ext.asyncio import AsyncSession

from extra import COMMON_PASSWORDS, PASSWORD_BAN_WORDS
from ldap_protocol.common_password_dao import CommonPasswordDAO
from ldap_protocol.password_ban_word_dao import PasswordBanWordDAO

# revision identifiers, used by Alembic.
revision = "ed84fda9c642"
down_revision = "ba78cef9700a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.create_table(
        "CommonPasswords",
        sa.Column("password", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("password"),
    )
    op.create_index(
        op.f("ix_CommonPasswords_password"),
        "CommonPasswords",
        ["password"],
        unique=True,
    )

    async def _create_common_passwords(connection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        common_password_dao = CommonPasswordDAO(session)

        for password in COMMON_PASSWORDS:
            await common_password_dao.create_one(password=password)

        await session.commit()

    op.run_async(_create_common_passwords)

    op.create_table(
        "PasswordBanWords",
        sa.Column("word", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("word"),
    )
    op.create_index(
        op.f("ix_PasswordBanWords_word"),
        "PasswordBanWords",
        ["word"],
        unique=True,
    )

    async def _create_password_ban_words(connection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()
        password_ban_word_dao = PasswordBanWordDAO(session)

        for ban_word in PASSWORD_BAN_WORDS:
            await password_ban_word_dao.create_one(word=ban_word)

        await session.commit()

    op.run_async(_create_password_ban_words)

    op.drop_column(
        "PasswordPolicies",
        "password_must_meet_complexity_requirements",
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_length",
            sa.Integer(),
            server_default="32",
            nullable=False,
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_lowercase_letters_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_uppercase_letters_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_letters_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_special_symbols_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_digits_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "min_unique_symbols_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_repeating_symbols_in_row_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_sequential_keyboard_symbols_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_sequential_alphabet_symbols_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.alter_column(
        "PasswordPolicies",
        "minimum_password_age_days",
        new_column_name="min_age_days",
    )
    op.alter_column(
        "PasswordPolicies",
        "maximum_password_age_days",
        new_column_name="max_age_days",
    )
    op.alter_column(
        "PasswordPolicies",
        "minimum_password_length",
        new_column_name="min_length",
    )
    op.alter_column(
        "PasswordPolicies",
        "password_history_length",
        new_column_name="history_length",
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
        "min_length",
        new_column_name="minimum_password_length",
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
    op.drop_column(
        "PasswordPolicies",
        "max_sequential_alphabet_symbols_count",
    )
    op.drop_column(
        "PasswordPolicies",
        "max_sequential_keyboard_symbols_count",
    )
    op.drop_column(
        "PasswordPolicies",
        "max_repeating_symbols_in_row_count",
    )
    op.drop_column(
        "PasswordPolicies",
        "min_unique_symbols_count",
    )
    op.drop_column(
        "PasswordPolicies",
        "min_digits_count",
    )
    op.drop_column(
        "PasswordPolicies",
        "min_special_symbols_count",
    )
    op.drop_column(
        "PasswordPolicies",
        "min_letters_count",
    )
    op.drop_column(
        "PasswordPolicies",
        "min_uppercase_letters_count",
    )
    op.drop_column(
        "PasswordPolicies",
        "min_lowercase_letters_count",
    )
    op.drop_column(
        "PasswordPolicies",
        "max_length",
    )
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

    op.drop_index("ix_PasswordBanWords_word", table_name="PasswordBanWords")
    op.drop_table("PasswordBanWords")

    op.drop_index("ix_CommonPasswords_password", table_name="CommonPasswords")
    op.drop_table("CommonPasswords")
