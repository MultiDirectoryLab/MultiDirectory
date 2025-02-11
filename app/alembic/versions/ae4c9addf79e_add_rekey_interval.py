"""Add session rekey interval.

Revision ID: ae4c9addf79e
Revises: dafg3a4b22ab
Create Date: 2025-02-10 16:22:02.675213

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'ae4c9addf79e'
down_revision = 'dafg3a4b22ab'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.add_column(
        'Policies',
        sa.Column(
            'session_rekey_interval',
            sa.Integer(),
            server_default='30',
            nullable=False,
        ),
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_column('Policies', 'session_rekey_interval')
