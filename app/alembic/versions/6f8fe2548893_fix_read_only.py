"""Fix Read-Only.

Revision ID: 6f8fe2548893
Revises: fafc3d0b11ec
Create Date: 2024-11-14 13:02:33.899640

"""
from alembic import op
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from ldap_protocol.utils.helpers import create_integer_hash
from models import Attribute, Directory

# revision identifiers, used by Alembic.
revision = '6f8fe2548893'
down_revision = 'fafc3d0b11ec'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    read_only_dir = session.scalar(select(Directory).where(
        Directory.name == 'readonly domain controllers'))

    if not read_only_dir:
        return

    session.execute(delete(Attribute).where(
        Attribute.name == 'objectSid', Attribute.directory == read_only_dir))
    session.execute(
        update(Attribute)
        .where(
            Attribute.name == 'sAMAccountName',
            Attribute.directory == read_only_dir,
            Attribute.value == 'domain users',
        )
        .values({'value': read_only_dir.name}),
    )

    attr_object_class = session.scalar(
        select(Attribute)
        .where(
            Attribute.name == 'objectClass',
            Attribute.directory == read_only_dir,
            Attribute.value == 'group',
        ),
    )
    if not attr_object_class:
        session.add(Attribute(
            name='objectClass', value='group', directory=read_only_dir))
        session.add(Attribute(
            name='gidNumber',
            value=str(create_integer_hash(read_only_dir.name)),
            directory=read_only_dir,
            ),
        )

    domain_sid = '-'.join(read_only_dir.object_sid.split('-')[:-1])
    read_only_dir.object_sid = domain_sid + '-521'

    session.commit()


def downgrade() -> None:
    """Downgrade."""
    pass
