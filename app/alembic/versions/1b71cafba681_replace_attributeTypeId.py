"""Delete attributeTypeId add attribute_type_name from AccessControlEntries.

Revision ID: 1b71cafba681
Revises: 708b01eaf025
Create Date: 2026-03-24 16:28:49.116712

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from ldap_protocol.roles.migrations_ace_dao import AccessControlEntryDirectoryMappingDAO
from ldap_protocol.utils.queries import get_base_directories

# revision identifiers, used by Alembic.
revision: None | str = "1b71cafba681"
down_revision: None | str = "708b01eaf025"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""

    async def _map_ace_to_directory_name(connection: AsyncConnection) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            ace_dao = await cnt.get(AccessControlEntryDirectoryMappingDAO)

        if not await get_base_directories(session):
            return

        await ace_dao.upgrade()
        await session.commit()

    op.add_column("AccessControlEntries", sa.Column("attribute_type_name", sa.String(), nullable=True))

    op.run_async(_map_ace_to_directory_name)

    op.drop_index(op.f("idx_ace_attribute_type_id"), table_name="AccessControlEntries", postgresql_using="hash")
    op.drop_constraint(
        op.f("AccessControlEntries_directoryAttributeTypeId_fkey"), "AccessControlEntries", type_="foreignkey"
    )
    op.drop_column("AccessControlEntries", "attributeTypeId")


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""

    async def _map_ace_to_directory_id(connection: AsyncConnection) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            ace_dao = await cnt.get(AccessControlEntryDirectoryMappingDAO)

        if not await get_base_directories(session):
            return

        await ace_dao.downgrade()
        await session.commit()

    op.add_column(
        "AccessControlEntries", sa.Column("attributeTypeId", sa.INTEGER(), autoincrement=False, nullable=True)
    )

    op.run_async(_map_ace_to_directory_id)

    op.create_foreign_key(
        op.f("AccessControlEntries_directoryAttributeTypeId_fkey"),
        "AccessControlEntries",
        "Directory",
        ["attributeTypeId"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        op.f("idx_ace_attribute_type_id"),
        "AccessControlEntries",
        ["attributeTypeId"],
        unique=False,
        postgresql_using="hash",
    )
    op.drop_column("AccessControlEntries", "attribute_type_name")
