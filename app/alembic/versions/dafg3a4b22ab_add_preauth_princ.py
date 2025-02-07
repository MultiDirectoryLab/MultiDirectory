"""Add preauth principals.

Revision ID: dafg3a4b22ab
Revises: f68a134a3685
Create Date: 2024-12-20 16:28:24.419163

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm import Session

from models import Attribute, User

# revision identifiers, used by Alembic.
revision = 'dafg3a4b22ab'
down_revision = 'f68a134a3685'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    for user in session.query(User):
        if user.sam_accout_name == 'krbadmin':
            continue

        username, domain = user.user_principal_name.split('@')
        principal = f"{username}@{domain.upper()}"

        attr_principal = session.scalar(
            sa.select(Attribute)
            .filter(
                Attribute.name == 'krbprincipalname',
                Attribute.value == principal,
            ),
        )
        if attr_principal:
            session.add(Attribute(
                name='krbticketflags',
                value='128',
                directory_id=attr_principal.directory_id,
            ))

    session.commit()


def downgrade() -> None:
    """Downgrade."""
    pass
