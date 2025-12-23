"""Add user reset password history permission to Domain Admins role.

Revision ID: a99f866a7e3a
Revises: 6c858cc05da7
Create Date: 2025-12-23 10:20:29.147813

"""

from alembic import op
from dishka import AsyncContainer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Role
from enums import AuthorizationRules, RoleConstants

# revision identifiers, used by Alembic.
revision: None | str = "a99f866a7e3a"
down_revision: None | str = "6c858cc05da7"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Upgrade."""

    async def _add_api_permission(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        query = (
            select(Role)
            .filter_by(name=RoleConstants.DOMAIN_ADMINS_ROLE_NAME)
        )  # fmt: skip
        role = (await session.scalars(query)).first()
        if role:
            role.permissions |= AuthorizationRules.USER_RESET_PASSWORD_HISTORY

    op.run_async(_add_api_permission)


def downgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Downgrade."""

    async def _remove_api_permission(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        query = (
            select(Role)
            .filter_by(name=RoleConstants.DOMAIN_ADMINS_ROLE_NAME)
        )  # fmt: skip
        role = (await session.scalars(query)).first()
        if role:
            role.permissions &= ~AuthorizationRules.USER_RESET_PASSWORD_HISTORY

    op.run_async(_remove_api_permission)
