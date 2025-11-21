"""Add auth_rules to roles table.

Revision ID: 4e8772277cfe
Revises: df4c52a613e5
Create Date: 2025-11-20 12:11:32.785993

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Role
from enums import AuthorizationRules
from ldap_protocol.roles.role_use_case import RoleConstants
from repo.pg.tables import queryable_attr as qa
from repo.pg.types import AuthorizationRulesType

# revision identifiers, used by Alembic.
revision: None | str = "4e8772277cfe"
down_revision: None | str = "df4c52a613e5"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade() -> None:
    """Upgrade."""

    async def _add_api_permissions(connection: AsyncConnection) -> None:
        session = AsyncSession(connection)
        await session.begin()
        query = (
            sa.select(Role)
            .where(qa(Role.name) == RoleConstants.DOMAIN_ADMINS_ROLE_NAME)
        )  # fmt: skip
        role = (await session.scalars(query)).first()
        all_permissions = AuthorizationRules.get_all()
        if role:
            role.auth_rules = AuthorizationRules(all_permissions)
            await session.commit()

    op.add_column(
        "Roles",
        sa.Column(
            "auth_rules",
            AuthorizationRulesType(),
            nullable=True,
        ),
    )
    op.run_async(_add_api_permissions)


def downgrade() -> None:
    """Downgrade."""
    op.drop_column("Roles", "auth_rules")
