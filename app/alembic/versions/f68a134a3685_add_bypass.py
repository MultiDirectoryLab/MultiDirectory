"""Add bypass.

Revision ID: f68a134a3685
Revises: bv546ccd35fa
Create Date: 2024-12-18 14:52:13.992686

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'f68a134a3685'
down_revision = 'bv546ccd35fa'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.add_column(
        'Policies',
        sa.Column(
            'bypass_no_connection',
            sa.Boolean(),
            server_default=sa.text('true'),
            nullable=False,
        ),
    )
    op.add_column(
        'Policies',
        sa.Column(
            'bypass_service_failure',
            sa.Boolean(),
            server_default=sa.text('true'),
            nullable=False,
        ),
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_column('Policies', 'bypass_service_failure')
    op.drop_column('Policies', 'bypass_no_connection')
