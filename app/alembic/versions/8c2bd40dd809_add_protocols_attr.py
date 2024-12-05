"""Add protocols attr.

Revision ID: 8c2bd40dd809
Revises: 6f8fe2548893
Create Date: 2024-12-04 16:24:35.521868

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from models import NetworkPolicy

# revision identifiers, used by Alembic.
revision = '8c2bd40dd809'
down_revision = '6f8fe2548893'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    policy_protocol_enum = sa.Enum(
        'WebAdminAPI',
        'LDAP',
        'Kerberos',
        name='policyprotocol',
    )
    policy_protocol_enum.create(op.get_bind(), checkfirst=True)
    op.add_column(
        'Policies',
        sa.Column(
            'protocols',
            postgresql.ARRAY(policy_protocol_enum),
        ),
    )

    bind = op.get_bind()
    session = Session(bind=bind)

    for policy in session.query(NetworkPolicy):
        policy.protocols = ['WebAdminAPI', 'LDAP']

    session.commit()

    op.alter_column('Policies', 'protocols', nullable=False)


def downgrade() -> None:
    """Downgrade."""
    op.drop_column('Policies', 'protocols')
