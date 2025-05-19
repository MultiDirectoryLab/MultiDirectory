"""Add RDN Attribute Naming and Resolve Duplication in KrbAdmin.

Revision ID: bf435bbd95ff
Revises: 196f0d327c6a
Create Date: 2024-10-23 10:46:24.419163

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from models import Attribute, Directory

# revision identifiers, used by Alembic.
revision = "bf435bbd95ff"
down_revision = "196f0d327c6a"
branch_labels = None
depends_on = None


def has_column(table_name: str, column_name: str, bind) -> bool:
    """Check if a column exists in a table."""
    inspector = inspect(bind)
    columns = [col["name"] for col in inspector.get_columns(table_name)]
    return bool(column_name in columns)


def upgrade() -> None:
    """Upgrade."""
    op.add_column("Directory", sa.Column("rdname", sa.String(length=64)))
    if not has_column("Directory", "entry_id", op.get_bind()):
        op.add_column(
            "Directory",
            sa.Column("entry_id", sa.Integer(), nullable=True),
        )

    bind = op.get_bind()
    session = Session(bind=bind)

    attrs = []
    for directory in session.query(Directory):
        if directory.is_domain:
            directory.rdname = ""
            continue

        rdname = directory.path[-1].split("=")[0]
        directory.rdname = rdname

        if rdname == "krbprincipalname":
            continue  # already exists

        attrs.append(
            Attribute(
                name=rdname,
                value=directory.name,
                directory_id=directory.id,
            )
        )

    session.add_all(attrs)
    session.commit()

    op.alter_column("Directory", "rdname", nullable=False)
    if has_column("Directory", "entry_id", op.get_bind()):
        op.drop_column("Directory", "entry_id")


def downgrade() -> None:
    """Downgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    if not has_column("Directory", "entry_id", op.get_bind()):
        op.add_column(
            "Directory",
            sa.Column("entry_id", sa.Integer(), nullable=True),
        )

    for directory in session.query(Directory):
        if directory.is_domain:
            directory.rdname = ""
            continue

        session.execute(
            sa.delete(Attribute)
            .where(
                Attribute.name == directory.rdname,
                Attribute.name != "krbprincipalname",
                Attribute.directory_id == directory.id,
            ),
        )  # fmt: skip

    op.drop_column("Directory", "rdname")
    if has_column("Directory", "entry_id", op.get_bind()):
        op.drop_column("Directory", "entry_id")
