"""Add Audit policies.

Revision ID: e4d6d99d32bd
Revises: ba78cef9700a
Create Date: 2025-03-26 08:04:54.853880

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.policies.audit_policies import AuditDAO
from ldap_protocol.utils.queries import get_base_directories

# revision identifiers, used by Alembic.
revision = "e4d6d99d32bd"
down_revision = "35d1542d2505"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade."""

    async def _create_audit_policies(connection) -> None:
        session = AsyncSession(bind=connection)

        if not await get_base_directories(session):
            return

        audit_dao = AuditDAO(session)
        await audit_dao.create_policies()
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
        sa.Column(
            "severity",
            sa.Enum(
                "EMERGENCY",
                "ALERT",
                "CRITICAL",
                "ERROR",
                "WARNING",
                "NOTICE",
                "INFO",
                "DEBUG",
                name="auditseverity",
            ),
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
        sa.Column("audit_policy_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["audit_policy_id"],
            ["AuditPolicies.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "AuditDestinations",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False, unique=True),
        sa.Column(
            "service_type",
            sa.Enum("SYSLOG", name="auditdestinationservicetype"),
            nullable=False,
        ),
        sa.Column(
            "is_enabled",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column(
            "protocol",
            sa.Enum("UDP", "TCP", name="auditdestinationprotocoltype"),
            nullable=False,
        ),
    )
    op.run_async(_create_audit_policies)


def downgrade() -> None:
    """Downgrade."""
    op.drop_table("AuditPolicyTriggers")
    op.drop_table("AuditPolicies")
    op.drop_table("AuditDestinations")

    op.execute(sa.text("DROP TYPE auditseverity"))
