"""Resolve Duplication in KrbAdmin.

Revision ID: bv546ccd35fa
Revises: 8c2bd40dd809
Create Date: 2024-12-10 10:46:24.419163

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm import Session

from models import Attribute, Directory

# revision identifiers, used by Alembic.
revision = "bv546ccd35fa"
down_revision = "8c2bd40dd809"
branch_labels = None
depends_on = None


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
                sa.delete(Attribute).where(
                    Attribute.name == attr,
                    Attribute.directory_id == krb_admin_user.id,
                ),
            )
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
            sa.delete(Attribute).where(
                Attribute.name == "gidNumber",
                Attribute.directory_id == krb_admin_group.id,
            ),
        )
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
    pass
