"""Migrate PasswordPolicy properties from Enterprise.

Revision ID: df4c52a613e5
Revises: f24ed0e49df2
Create Date: 2025-11-18 14:56:02.122357

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import Session

from entities import PasswordPolicy
from ldap_protocol.policies.password.ban_word_repository import (
    PasswordBanWordRepository,
)

# revision identifiers, used by Alembic.
revision: None | str = "df4c52a613e5"
down_revision: None | str = "f24ed0e49df2"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None

with open("extra/common_passwords.txt") as f:
    _BAN_WORDS = set(f.read().split("\n"))


def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    op.create_table(
        "PasswordBanWords",
        sa.Column("word", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("word"),
    )

    op.execute(
        sa.text(
            "CREATE INDEX IF NOT EXISTS idx_password_ban_words_word_gin_trgm "
            'ON "PasswordBanWords" USING GIN(word gin_trgm_ops);',
        ),
    )

    async def _create_common_passwords(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        password_ban_word_repo = PasswordBanWordRepository(session)
        await password_ban_word_repo.replace(_BAN_WORDS)

        await session.commit()

    op.run_async(_create_common_passwords)

    op.drop_column(
        "PasswordPolicies",
        "password_must_meet_complexity_requirements",
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column("language", sa.String(length=255), nullable=True),
    )
    session.execute(update(PasswordPolicy).values({"language": "Latin"}))
    op.alter_column("PasswordPolicies", "language", nullable=False)

    op.add_column(
        "PasswordPolicies",
        sa.Column("is_exact_match", sa.Boolean(), nullable=True),
    )
    session.execute(update(PasswordPolicy).values({"is_exact_match": True}))
    op.alter_column("PasswordPolicies", "is_exact_match", nullable=False)

    op.add_column(
        "PasswordPolicies",
        sa.Column("max_length", sa.Integer(), nullable=True),
    )
    session.execute(update(PasswordPolicy).values({"max_length": 32}))
    op.alter_column("PasswordPolicies", "max_length", nullable=False)

    op.add_column(
        "PasswordPolicies",
        sa.Column("min_lowercase_letters_count", sa.Integer(), nullable=True),
    )
    session.execute(
        update(PasswordPolicy).values({"min_lowercase_letters_count": 0}),
    )
    op.alter_column(
        "PasswordPolicies",
        "min_lowercase_letters_count",
        nullable=False,
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column("min_uppercase_letters_count", sa.Integer(), nullable=True),
    )
    session.execute(
        update(PasswordPolicy).values({"min_uppercase_letters_count": 0}),
    )
    op.alter_column(
        "PasswordPolicies",
        "min_uppercase_letters_count",
        nullable=False,
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column("min_special_symbols_count", sa.Integer(), nullable=True),
    )
    session.execute(
        update(PasswordPolicy).values({"min_special_symbols_count": 0}),
    )
    op.alter_column(
        "PasswordPolicies",
        "min_special_symbols_count",
        nullable=False,
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column("min_digits_count", sa.Integer(), nullable=True),
    )
    session.execute(update(PasswordPolicy).values({"min_digits_count": 0}))
    op.alter_column(
        "PasswordPolicies",
        "min_digits_count",
        nullable=False,
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column("min_unique_symbols_count", sa.Integer(), nullable=True),
    )
    session.execute(
        update(PasswordPolicy).values({"min_unique_symbols_count": 0}),
    )
    op.alter_column(
        "PasswordPolicies",
        "min_unique_symbols_count",
        nullable=False,
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_repeating_symbols_in_row_count",
            sa.Integer(),
            nullable=True,
        ),
    )
    session.execute(
        update(PasswordPolicy).values(
            {"max_repeating_symbols_in_row_count": 0},
        ),
    )
    op.alter_column(
        "PasswordPolicies",
        "max_repeating_symbols_in_row_count",
        nullable=False,
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_sequential_keyboard_symbols_count",
            sa.Integer(),
            nullable=True,
        ),
    )
    session.execute(
        update(PasswordPolicy).values(
            {"max_sequential_keyboard_symbols_count": 0},
        ),
    )
    op.alter_column(
        "PasswordPolicies",
        "max_sequential_keyboard_symbols_count",
        nullable=False,
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "max_sequential_alphabet_symbols_count",
            sa.Integer(),
            nullable=True,
        ),
    )
    session.execute(
        update(PasswordPolicy).values(
            {"max_sequential_alphabet_symbols_count": 0},
        ),
    )
    op.alter_column(
        "PasswordPolicies",
        "max_sequential_alphabet_symbols_count",
        nullable=False,
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column("max_failed_attempts", sa.Integer(), nullable=True),
    )
    session.execute(update(PasswordPolicy).values({"max_failed_attempts": 6}))
    op.alter_column("PasswordPolicies", "max_failed_attempts", nullable=False)

    op.add_column(
        "PasswordPolicies",
        sa.Column("failed_attempts_reset_sec", sa.Integer(), nullable=True),
    )
    session.execute(
        update(PasswordPolicy).values({"failed_attempts_reset_sec": 60}),
    )
    op.alter_column(
        "PasswordPolicies",
        "failed_attempts_reset_sec",
        nullable=False,
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column("lockout_duration_sec", sa.Integer(), nullable=True),
    )
    session.execute(
        update(PasswordPolicy).values({"lockout_duration_sec": 600}),
    )
    op.alter_column(
        "PasswordPolicies",
        "lockout_duration_sec",
        nullable=False,
    )

    op.add_column(
        "PasswordPolicies",
        sa.Column("fail_delay_sec", sa.Integer(), nullable=True),
    )
    session.execute(update(PasswordPolicy).values({"fail_delay_sec": 5}))
    op.alter_column("PasswordPolicies", "fail_delay_sec", nullable=False)

    op.drop_constraint(
        op.f("PasswordPolicies_priority_key"),
        "PasswordPolicies",
        type_="unique",
    )
    op.create_unique_constraint(
        "PasswordPolicies_priority_uc",
        "PasswordPolicies",
        ["priority"],
        deferrable=True,
        initially="DEFERRED",
    )


def downgrade() -> None:
    """Downgrade."""
    op.execute(
        sa.text("DROP INDEX IF EXISTS idx_password_ban_words_word_gin_trgm"),
    )
    op.drop_table("PasswordBanWords")

    op.drop_constraint(
        "PasswordPolicies_priority_uc",
        "PasswordPolicies",
        type_="unique",
    )
    op.create_unique_constraint(
        op.f("PasswordPolicies_priority_key"),
        "PasswordPolicies",
        ["priority"],
        postgresql_nulls_not_distinct=False,
    )
    op.drop_column("PasswordPolicies", "fail_delay_sec")
    op.drop_column("PasswordPolicies", "lockout_duration_sec")
    op.drop_column("PasswordPolicies", "failed_attempts_reset_sec")
    op.drop_column("PasswordPolicies", "max_failed_attempts")
    op.drop_column("PasswordPolicies", "max_sequential_alphabet_symbols_count")
    op.drop_column("PasswordPolicies", "max_sequential_keyboard_symbols_count")
    op.drop_column("PasswordPolicies", "max_repeating_symbols_in_row_count")
    op.drop_column("PasswordPolicies", "min_unique_symbols_count")
    op.drop_column("PasswordPolicies", "min_digits_count")
    op.drop_column("PasswordPolicies", "min_special_symbols_count")
    op.drop_column("PasswordPolicies", "min_uppercase_letters_count")
    op.drop_column("PasswordPolicies", "min_lowercase_letters_count")
    op.drop_column("PasswordPolicies", "max_length")
    op.drop_column("PasswordPolicies", "is_exact_match")
    op.drop_column("PasswordPolicies", "language")

    op.add_column(
        "PasswordPolicies",
        sa.Column(
            "password_must_meet_complexity_requirements",
            sa.BOOLEAN(),
            autoincrement=False,
            nullable=True,
        ),
    )
    op.execute(
        sa.text(
            'UPDATE "PasswordPolicies" '
            "SET password_must_meet_complexity_requirements = FALSE",
        ),
    )
    op.alter_column(
        "PasswordPolicies",
        "password_must_meet_complexity_requirements",
        nullable=False,
    )
