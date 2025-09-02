"""Fix Read-Only.

Revision ID: 6f8fe2548893
Revises: fafc3d0b11ec
Create Date: 2024-11-14 13:02:33.899640

"""

from alembic import op
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from extra.alembic_utils import temporary_stub_entity_type_name
from ldap_protocol.utils.helpers import create_integer_hash
from models import Attribute, Directory, directory_table

# revision identifiers, used by Alembic.
revision = "6f8fe2548893"
down_revision = "fafc3d0b11ec"
branch_labels: None = None
depends_on: None = None


@temporary_stub_entity_type_name
def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    ro_dir = session.scalar(
        select(Directory)
        .where(directory_table.c.name == "readonly domain controllers"),
    )  # fmt: skip

    if ro_dir:
        session.execute(
            delete(Attribute)
            .filter_by(name="objectSid", directory=ro_dir),
        )  # fmt: skip
        session.execute(
            update(Attribute)
            .filter_by(
                name="sAMAccountName",
                directory=ro_dir,
                value="domain users",
            )
            .values({"value": ro_dir.name}),
        )

        attr_object_class = session.scalar(
            select(Attribute)
            .filter_by(
                name="objectClass",
                directory=ro_dir,
                value="group",
            ),
        )  # fmt: skip
        if not attr_object_class:
            session.add(
                Attribute(
                    name="objectClass",
                    value="group",
                    directory_id=ro_dir.id,
                ),
            )
            session.add(
                Attribute(
                    name=ro_dir.rdname,
                    value=ro_dir.name,
                    directory_id=ro_dir.id,
                ),
            )
            session.add(
                Attribute(
                    name="gidNumber",
                    value=str(create_integer_hash(ro_dir.name)),
                    directory_id=ro_dir.id,
                ),
            )

        domain_sid = "-".join(ro_dir.object_sid.split("-")[:-1])
        ro_dir.object_sid = domain_sid + "-521"

        session.commit()


def downgrade() -> None:
    """Downgrade."""
