"""Add RDN Attribute Naming and Resolve Duplication in KrbAdmin.

Revision ID: bf435bbd95ff
Revises: 59e98bbd8ad8
Create Date: 2024-10-23 10:46:24.419163

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm import Session

from models import Attribute, Directory

# revision identifiers, used by Alembic.
revision = 'bf435bbd95ff'
down_revision = '196f0d327c6a'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.add_column('Directory', sa.Column('rdname', sa.String(length=64)))

    bind = op.get_bind()
    session = Session(bind=bind)

    attrs = []

    for directory in session.query(Directory):
        if directory.is_domain:
            directory.rdname = ''
            continue

        rdname = directory.path[-1].split('=')[0]
        directory.rdname = rdname

        if rdname == 'krbprincipalname':
            continue  # already exists

        attrs.append(Attribute(
            name=rdname,
            value=directory.name,
            directory_id=directory.id,
        ))

    krb_admin_dir = session.query(Directory).filter_by(name='krbadmin').first()

    for attr, new_value in {
        "loginShell": "/bin/false",
        "uidNumber": "800",
        "homeDirectory": "/home/krbadmin",
    }:
        session.execute(
            sa.update(Attribute)
            .where(
                Attribute.name == attr,
                Attribute.directory_id == krb_admin_dir.id,
                Attribute.value == new_value,
            )
            .values(value=new_value),
        )

    session.add_all(attrs)
    session.commit()

    op.alter_column('Directory', 'rdname', nullable=False)


def downgrade() -> None:
    """Downgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    for directory in session.query(Directory):
        if directory.is_domain:
            directory.rdname = ''
            continue

        session.execute(
            sa.delete(Attribute)
            .where(
                Attribute.name == directory.rdname,
                Attribute.name != 'krbprincipalname',
                Attribute.directory_id == directory.id,
            ),
        )

    op.drop_column('Directory', 'rdname')
