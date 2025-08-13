"""Alembic utils."""

from typing import Callable

import sqlalchemy as sa
from alembic import op


def temporary_stub_entity_type_name(func: Callable) -> Callable:
    """Add and drop the 'entity_type_name' column in the 'Directory' table.

    State of the database at the time of migration
    doesn't contain 'entity_type_name' column in the 'Directory' table,
    but 'Directory' model has the column.

    Before starting the migration, add 'entity_type_name' column.
    Then migration completed, delete 'entity_type_name' column.

    Don`t like excluding columns with Deferred(),
    because you will need to refactor SQL queries
    that precede the 'ba78cef9700a_initial_entity_type.py' migration
    and include working with the Directory.

    :param Callable func: any function
    :return Callable: any function
    """

    def wrapper(*args, **kwargs):
        op.add_column(
            "Directory",
            sa.Column("entity_type_id", sa.Integer(), nullable=True),
        )
        func(*args, **kwargs)
        op.drop_column("Directory", "entity_type_id")
        return None

    return wrapper


def temporary_stub_lockout_fields(func: Callable) -> Callable:
    """Add and drop lockout-related columns in Users and PasswordPolicies.

    State of the database at the time of migration
    doesn't contain lockout-related columns, but models have these columns.

    Before starting the migration, add lockout columns.
    Then migration completed, delete lockout columns.

    :param Callable func: any function
    :return Callable: any function
    """

    def wrapper(*args: tuple, **kwargs: dict) -> None:
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

        func(*args, **kwargs)

        op.drop_column("PasswordPolicies", "fail_delay_sec")
        op.drop_column("PasswordPolicies", "lockout_duration_sec")
        op.drop_column("PasswordPolicies", "failed_attempts_reset_sec")
        op.drop_column("PasswordPolicies", "max_failed_attempts")

        op.drop_column("Users", "is_auth_locked")
        op.drop_column("Users", "last_failed_auth")
        op.drop_column("Users", "failed_auth_attempts")

        return None

    return wrapper
