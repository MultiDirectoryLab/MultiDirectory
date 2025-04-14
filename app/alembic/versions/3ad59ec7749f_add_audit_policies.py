"""Add Audit policies.

Revision ID: e4d6d99d32bd
Revises: 4442d1d982a4
Create Date: 2025-03-26 08:04:54.853880

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.utils.queries import add_audit_pocilies

# revision identifiers, used by Alembic.
revision = "e4d6d99d32bd"
down_revision = "4442d1d982a4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""

    async def _create_audit_policies(connection) -> None:
        session = AsyncSession(bind=connection)

        result = await session.execute(sa.text('SELECT id FROM "Directory"'))

        if not result.scalar_one_or_none():
            return

        await add_audit_pocilies(session)
        await session.commit()

    op.create_table(
        "AuditPolicies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "is_enabled",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "AuditPolicyTriggers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "is_ldap",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column(
            "is_http",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("operation_code", sa.Integer(), nullable=False),
        sa.Column("object_class", sa.String(), nullable=False),
        sa.Column(
            "additional_info",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("operation_success", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "AuditPolicyTriggersMemberships",
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("trigger_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id"], ["AuditPolicies.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["trigger_id"], ["AuditPolicyTriggers.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("policy_id", "trigger_id"),
    )
    op.run_async(_create_audit_policies)


def downgrade() -> None:
    """Downgrade."""
    op.drop_table("AuditPolicyTriggersMemberships")
    op.drop_table("AuditPolicyTriggers")
    op.drop_table("AuditPolicies")
