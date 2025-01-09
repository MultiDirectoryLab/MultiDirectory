"""Add Audit policies.

Revision ID: 3ad59ec7749f
Revises: f68a134a3685
Create Date: 2024-11-25 10:25:11.367772

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.utils.queries import add_audit_pocilies

# revision identifiers, used by Alembic.
revision = '3ad59ec7749f'
down_revision = 'f68a134a3685'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""
    async def _create_audit_policies(connection) -> None:
        session = AsyncSession(bind=connection)
        await add_audit_pocilies(session)
        await session.commit()

    op.create_table(
        'AuditPolicies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column("actions", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column('condition_attributes', sa.JSON(), nullable=False),
        sa.Column('change_attributes', sa.JSON()),
        sa.Column("operation_success", sa.Boolean(), nullable=False),
        sa.Column(
            "is_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    op.run_async(_create_audit_policies)


def downgrade() -> None:
    """Downgrade."""
    op.drop_table('AuditPolicies')
