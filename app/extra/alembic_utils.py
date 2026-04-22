"""Alembic utils."""

from typing import Any, Callable

import sqlalchemy as sa
from alembic import op


def temporary_stub_column(table_name: str, column_name: str, type_: Any) -> Callable:
    """Add and drop a temporary column in the table.

    State of the database at the time of migration
    doesn't contain the specified column in the table,
    but model has the column.

    Before starting the migration, add the specified column.
    Then migration completed, delete the column.

    Don`t like excluding columns with Deferred(),
    because you will need to refactor SQL queries
    that precede migrations and include working with the Directory.

    :param str column_name: column name to temporarily add
    :return Callable: decorator function
    """

    def decorator(func: Callable) -> Callable:
        def wrapper(*args: tuple, **kwargs: dict) -> None:
            op.add_column(table_name, sa.Column(column_name, type_, nullable=True))
            func(*args, **kwargs)
            op.drop_column(table_name, column_name)
            return None

        return wrapper

    return decorator
