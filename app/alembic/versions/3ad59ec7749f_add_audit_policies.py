"""Add Audit policies.

Revision ID: 3ad59ec7749f
Revises: 6f8fe2548893
Create Date: 2024-11-25 10:25:11.367772

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '3ad59ec7749f'
down_revision = '6f8fe2548893'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    op.create_table(
        'AuditPolicies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('trigger', sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )


def downgrade() -> None:
    """Downgrade."""
    op.drop_table('AuditPolicies')
