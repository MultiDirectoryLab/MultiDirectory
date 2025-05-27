"""Alembic utils."""

from typing import Callable

import sqlalchemy as sa
from alembic import op


def add_and_drop_entry_id(func: Callable) -> Callable:
    """Add and drop the 'entry_id' column in the 'Directory' table.

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
