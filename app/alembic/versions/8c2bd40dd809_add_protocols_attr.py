"""Add protocols attrs.

Revision ID: 8c2bd40dd809
Revises: 6f8fe2548893
Create Date: 2024-12-04 16:24:35.521868

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm import Session

from models import NetworkPolicy

# revision identifiers, used by Alembic.
revision = '8c2bd40dd809'
down_revision = '6f8fe2548893'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    for protocol_field in ("is_http", "is_ldap", "is_kerberos"):
        op.add_column(
            'Policies',
            sa.Column(
                protocol_field,
                sa.Boolean(),
                server_default=sa.text('false'),
            ),
        )

    bind = op.get_bind()
    session = Session(bind=bind)

    for policy in session.query(NetworkPolicy):
        policy.is_ldap = True
        policy.is_http = True
        policy.is_kerberos = True

    session.commit()

    for protocol_field in ("is_http", "is_ldap", "is_kerberos"):
        op.alter_column('Policies', protocol_field, nullable=False)


def downgrade() -> None:
    """Downgrade."""
    op.drop_column('Policies', 'is_ldap')
    op.drop_column('Policies', 'is_http')
    op.drop_column('Policies', 'is_kerberos')
