"""Alembic utils."""

from typing import Callable

import sqlalchemy as sa
from alembic import op


def add_and_drop_entry_id(func: Callable) -> Callable:
    """Add and drop the 'entry_id' column in the 'Directory' table.

    State of the database at the time of migration
    doesn`t contains 'entry_id' column into 'Directory' table,
    but 'Directory' model has the column.

    Before starting the migration, add 'entry_id' column.
    Then migration complited, delete 'entry_id' column.

    Don`t like excluding columns with Deferred(),
    because you will need to refactor SQL queries
    that precede the 'ba78cef9700a_initial_ldap_entry.py' migration
    and include working with the Directory.

    :param Callable func: any function
    :return Callable: any function
    """

    def wrapper(*args, **kwargs):
        op.add_column(
            "Directory",
            sa.Column("entry_id", sa.Integer(), nullable=True),
        )
        func(*args, **kwargs)
        op.drop_column("Directory", "entry_id")
        return None

    return wrapper
