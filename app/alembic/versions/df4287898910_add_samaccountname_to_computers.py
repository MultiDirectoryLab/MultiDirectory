"""Add sAMAccountName attribute to Computer directories.

Revision ID: df4287898910
Revises: 19d86e660cf2
Create Date: 2026-03-10 07:33:43.493288

"""

from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import selectinload

from entities import Attribute, Directory, EntityType
from enums import EntityTypeNames
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "df4287898910"
down_revision: None | str = "19d86e660cf2"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None

_ATTR_NAME_SAMACCOUNTNAME = "sAMAccountName"


def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""

    async def _add_samaccountname_attr_to_computers(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        computer_dirs = await session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .options(selectinload(qa(Directory.attributes)))
            .where(
                qa(EntityType.name) == EntityTypeNames.COMPUTER,
                ~exists(
                    select(qa(Attribute.id))
                    .where(
                        qa(Attribute.directory_id) == qa(Directory.id),
                        qa(Attribute.name) == _ATTR_NAME_SAMACCOUNTNAME,
                    ),
                ),
            ),
        )  # fmt: skip

        for directory in computer_dirs:
            session.add(
                Attribute(
                    name=_ATTR_NAME_SAMACCOUNTNAME,
                    value=directory.name,
                    directory_id=directory.id,
                ),
            )

        await session.commit()

    op.run_async(_add_samaccountname_attr_to_computers)


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""

    async def _remove_samaccountname_attr_from_computers(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        computer_dirs = await session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .options(selectinload(qa(Directory.attributes)))
            .where(qa(EntityType.name) == EntityTypeNames.COMPUTER),
        )

        for directory in computer_dirs:
            for attr in directory.attributes:
                if attr.name == _ATTR_NAME_SAMACCOUNTNAME:
                    await session.delete(attr)
                    break

        await session.commit()

    op.run_async(_remove_samaccountname_attr_from_computers)
