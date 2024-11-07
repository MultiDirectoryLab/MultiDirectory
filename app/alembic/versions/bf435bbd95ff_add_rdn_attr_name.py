"""Add rdn attr name.

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
    op.add_column('Directory', sa.Column('rdn_attr', sa.String(length=64)))

    bind = op.get_bind()
    session = Session(bind=bind)

    attrs = []

    for directory in session.query(Directory):
        if directory.is_domain:
            directory.rdn_attr = ''
            continue

        rdn_attr = directory.path[-1].split('=')[0]
        directory.rdn_attr = rdn_attr

        if rdn_attr == 'krbprincipalname':
            continue  # already exists

        attrs.append(Attribute(
            name=rdn_attr,
            value=directory.name,
            directory_id=directory.id,
        ))

    session.add_all(attrs)
    session.commit()

    op.alter_column('Directory', 'rdn_attr', nullable=False)


def downgrade() -> None:
    """Downgrade."""
    op.drop_column('Directory', 'rdn_attr')
