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

    Returns:
        Callable: any function
    """

    def wrapper(*args, **kwargs):
        op.add_column(
            "Directory",
            sa.Column("entity_type_name", sa.String(255), nullable=True),
        )
        func(*args, **kwargs)
        op.drop_column("Directory", "entity_type_name")
        return None

    return wrapper
