"""Resolve Duplication in KrbAdmin.

Revision ID: bv546ccd35fa
Revises: 8c2bd40dd809
Create Date: 2024-12-10 10:46:24.419163

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm import Session

from extra.alembic_utils import temporary_stub_entity_type_id
from models import Attribute, Directory

# revision identifiers, used by Alembic.
revision = "bv546ccd35fa"
down_revision = "8c2bd40dd809"
branch_labels = None
depends_on = None


@temporary_stub_entity_type_id
def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    krb_admin_user = session.scalar(
        sa.select(Directory)
        .join(Directory.user)
        .filter(Directory.name == "krbadmin"),
    )

    if krb_admin_user:
        for attr, new_value in {
            "loginShell": "/bin/false",
            "uidNumber": "800",
            "gidNumber": "800",
            "homeDirectory": "/home/krbadmin",
        }.items():
            session.execute(
                sa.delete(Attribute)
                .where(
                    Attribute.name == attr,
                    Attribute.directory_id == krb_admin_user.id,
                ),
            )  # fmt: skip
            session.add(
                Attribute(
                    name=attr,
                    value=new_value,
                    directory_id=krb_admin_user.id,
                )
            )

        krb_admin_group = session.scalar(
            sa.select(Directory)
            .join(Directory.group)
            .filter(Directory.name == "krbadmin"),
        )

        session.execute(
            sa.delete(Attribute)
            .where(
                Attribute.name == "gidNumber",
                Attribute.directory_id == krb_admin_group.id,
            ),
        )  # fmt: skip
        session.add(
            Attribute(
                name="gidNumber",
                value="800",
                directory_id=krb_admin_group.id,
            )
        )

    session.commit()


def downgrade() -> None:
    """Downgrade."""
