"""Fix Read-Only.

Revision ID: 6f8fe2548893
Revises: fafc3d0b11ec
Create Date: 2024-11-14 13:02:33.899640

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from ldap_protocol.utils.helpers import create_integer_hash
from models import Attribute, Directory

# revision identifiers, used by Alembic.
revision = "6f8fe2548893"
down_revision = "fafc3d0b11ec"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    op.add_column(
        "Directory",
        sa.Column("entry_id", sa.Integer(), nullable=True),
    )

    ro_dir = session.scalar(
        select(Directory)
        .where(Directory.name == "readonly domain controllers")
    )  # fmt: skip

    op.drop_column("Directory", "entry_id")
    if not ro_dir:
        return

    op.add_column(
        "Directory",
        sa.Column("entry_id", sa.Integer(), nullable=True),
    )

    session.execute(
        delete(Attribute)
        .where(Attribute.name == "objectSid", Attribute.directory == ro_dir)
    )  # fmt: skip
    session.execute(
        update(Attribute)
        .where(
            Attribute.name == "sAMAccountName",
            Attribute.directory == ro_dir,
            Attribute.value == "domain users",
        )
        .values({"value": ro_dir.name}),
    )

    attr_object_class = session.scalar(
        select(Attribute)
        .where(
            Attribute.name == "objectClass",
            Attribute.directory == ro_dir,
            Attribute.value == "group",
        ),
    )  # fmt: skip
    if not attr_object_class:
        session.add(
            Attribute(
                name="objectClass",
                value="group",
                directory=ro_dir,
            ),
        )
        session.add(
            Attribute(
                name=ro_dir.rdname,
                value=ro_dir.name,
                directory=ro_dir,
            ),
        )
        session.add(
            Attribute(
                name="gidNumber",
                value=str(create_integer_hash(ro_dir.name)),
                directory=ro_dir,
            ),
        )

    domain_sid = "-".join(ro_dir.object_sid.split("-")[:-1])
    ro_dir.object_sid = domain_sid + "-521"

    session.commit()

    op.drop_column("Directory", "entry_id")


def downgrade() -> None:
    """Downgrade."""
