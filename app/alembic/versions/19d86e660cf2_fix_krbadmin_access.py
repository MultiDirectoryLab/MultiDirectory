"""Fix krbadmin access.

Revision ID: 19d86e660cf2
Revises: 2dadf40c026a
Create Date: 2026-02-19 11:40:15.805997

"""

from alembic import op
from dishka import AsyncContainer
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from enums import RoleConstants
from ldap_protocol.roles.exceptions import RoleNotFoundError
from ldap_protocol.roles.role_dao import RoleDAO
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.utils.queries import get_base_directories

# revision identifiers, used by Alembic.
revision: None | str = "19d86e660cf2"
down_revision: None | str = "2dadf40c026a"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""

    async def _fix_krbadmin_role(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container() as cnt:
            session = await cnt.get(AsyncSession)
            role_dao = await cnt.get(RoleDAO)
            role_use_case = await cnt.get(RoleUseCase)

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return

        try:
            await role_dao.get_by_name(RoleConstants.KERBEROS_ROLE_NAME)
        except RoleNotFoundError:
            return
        else:
            await role_use_case.add_read_only_role_to_krbadmin_group()

        await session.commit()

    op.run_async(_fix_krbadmin_role)


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""
