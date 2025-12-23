"""Add permissions to roles table.

Revision ID: 4e8772277cfe
Revises: df4c52a613e5
Create Date: 2025-11-20 12:11:32.785993

"""

from alembic import op
from dishka import AsyncContainer
from sqlalchemy import Column, select, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Role
from enums import AuthorizationRules, RoleConstants
from repo.pg.types import AuthorizationRulesType

# revision identifiers, used by Alembic.
revision: None | str = "4e8772277cfe"
down_revision: None | str = "df4c52a613e5"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Upgrade."""

    async def _add_api_permissions(connection: AsyncConnection) -> None:
        session = AsyncSession(connection)
        await session.begin()
        query = (
            select(Role)
            .filter_by(name=RoleConstants.DOMAIN_ADMINS_ROLE_NAME)
        )  # fmt: skip
        role = (await session.scalars(query)).first()
        if role:
            role.permissions = AuthorizationRules.get_all()
            await session.commit()

    op.add_column(
        "Roles",
        Column(
            "permissions",
            AuthorizationRulesType(),
            nullable=False,
            server_default=text("'\\x00'::bytea"),
        ),
    )
    op.run_async(_add_api_permissions)


def downgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Downgrade."""
    op.drop_column("Roles", "permissions")
