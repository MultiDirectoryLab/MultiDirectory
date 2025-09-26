"""Add RDN Attribute Naming and Resolve Duplication in KrbAdmin.

Revision ID: bf435bbd95ff
Revises: 196f0d327c6a
Create Date: 2024-10-23 10:46:24.419163

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm import Session

from extra.alembic_utils import temporary_stub_entity_type_name
from models import Attribute, Directory, attributes_table

# revision identifiers, used by Alembic.
revision = "bf435bbd95ff"
down_revision = "196f0d327c6a"
branch_labels: None | str = None
depends_on: None | str = None


@temporary_stub_entity_type_name
def upgrade() -> None:
    """Upgrade."""
    op.add_column("Directory", sa.Column("rdname", sa.String(length=64)))

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
            ),
        )

    session.add_all(attrs)
    session.commit()

    op.alter_column("Directory", "rdname", nullable=False)


@temporary_stub_entity_type_name
def downgrade() -> None:
    """Downgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    for directory in session.query(Directory):
        if directory.is_domain:
            directory.rdname = ""
            continue

        session.execute(
            sa.delete(Attribute)
            .where(
                attributes_table.c.name == directory.rdname,
                attributes_table.c.name != "krbprincipalname",
                attributes_table.c.directory_id == directory.id,
            ),
        )  # fmt: skip

    op.drop_column("Directory", "rdname")
