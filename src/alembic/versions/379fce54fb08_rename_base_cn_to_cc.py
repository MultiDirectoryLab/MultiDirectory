"""Rename base containers.

users -> Users, groups -> Groups, computers -> Computers.

Revision ID: 379fce54fb08
Revises: ec45e3e8aa0f
Create Date: 2026-01-23 12:26:10.758698

"""

from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from domain.entities import Attribute, Directory
from infrastructure.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "379fce54fb08"
down_revision: None | str = "ec45e3e8aa0f"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


CONTAINER_RENAMES = {
    "users": "Users",
    "groups": "Groups",
    "computers": "Computers",
}


async def _update_descendants(
    session: AsyncSession,
    parent_id: int,
    cn_from: str,
    cn_to: str,
) -> None:
    """Recursively update paths of all descendants."""
    child_dirs = await session.scalars(
        select(Directory).where(qa(Directory.parent_id) == parent_id),
    )

    for child_dir in child_dirs:
        child_dir.path = [cn_to if p == cn_from else p for p in child_dir.path]
        await session.flush()
        await _update_descendants(
            session,
            child_dir.id,
            cn_from=cn_from,
            cn_to=cn_to,
        )


async def _update_attributes(
    session: AsyncSession,
    old_value: str,
    new_value: str,
) -> None:
    """Update attribute values containing old DN references."""
    result = await session.execute(
        select(Attribute).where(
            qa(Attribute.value).ilike(f"%{old_value}%"),
        ),
    )
    attributes = result.scalars().all()

    for attr in attributes:
        if attr.value and old_value in attr.value:
            attr.value = attr.value.replace(old_value, new_value)

    await session.flush()


async def _rename_container(
    session: AsyncSession,
    old_name: str,
    new_name: str,
) -> None:
    """Rename a single container and update all references."""
    container_dir = await session.scalar(
        select(Directory).where(
            qa(Directory.name) == old_name,
            qa(Directory.is_system).is_(True),
        ),
    )

    if not container_dir:
        return

    cn_from = f"cn={old_name}"
    cn_to = f"cn={new_name}"

    container_dir.name = new_name
    container_dir.path = [
        cn_to if p == cn_from else p for p in container_dir.path
    ]

    await session.flush()

    await _update_descendants(
        session,
        container_dir.id,
        cn_from=cn_from,
        cn_to=cn_to,
    )

    await _update_attributes(session, cn_from, cn_to)


def upgrade(container: AsyncContainer) -> None:
    """Upgrade: Rename containers to capitalized versions."""

    async def _rename_containers(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        for old_name, new_name in CONTAINER_RENAMES.items():
            await _rename_container(session, old_name, new_name)

        await session.commit()

    op.run_async(_rename_containers)


def downgrade(container: AsyncContainer) -> None:
    """Downgrade: Rename containers back to lowercase."""

    async def _rename_containers_back(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        for old_name, new_name in CONTAINER_RENAMES.items():
            await _rename_container(session, new_name, old_name)

        await session.commit()

    op.run_async(_rename_containers_back)
