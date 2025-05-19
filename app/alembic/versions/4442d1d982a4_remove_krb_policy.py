"""Remove default_policy.

Revision ID: 4442d1d982a4
Revises: 692ae64e0cc5
Create Date: 2025-02-28 12:01:56.745334

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import delete, inspect
from sqlalchemy.orm import Session

from models import Attribute, Directory

# revision identifiers, used by Alembic.
revision = "4442d1d982a4"
down_revision = "692ae64e0cc5"
branch_labels = None
depends_on = None


def has_column(table_name: str, column_name: str, bind) -> bool:
    """Check if a column exists in a table."""
    inspector = inspect(bind)
    columns = [col["name"] for col in inspector.get_columns(table_name)]
    return bool(column_name in columns)


def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    if not has_column("Directory", "entry_id", op.get_bind()):
        op.add_column(
            "Directory",
            sa.Column("entry_id", sa.Integer(), nullable=True),
        )

    session.execute(delete(Directory).filter_by(name="default_policy"))
    session.execute(delete(Attribute).filter_by(name="krbpwdpolicyreference"))

    if has_column("Directory", "entry_id", op.get_bind()):
        op.drop_column("Directory", "entry_id")


def downgrade() -> None:
    """Downgrade."""
    if has_column("Directory", "entry_id", op.get_bind()):
        op.drop_column("Directory", "entry_id")
