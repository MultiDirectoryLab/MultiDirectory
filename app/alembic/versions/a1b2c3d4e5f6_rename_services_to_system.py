"""Rename services container to System for AD compatibility.

Revision ID: a1b2c3d4e5f6
Revises: 6c858cc05da7
Create Date: 2026-01-13 12:00:00.000000

"""

from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Attribute, Directory
from infrasture.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "a1b2c3d4e5f6"
down_revision: None | str = "c5a9b3f2e8d7"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


async def _update_descendants(
    session: AsyncSession,
    parent_id: int,
    ou_from: str,
    ou_to: str,
) -> None:
    """Recursively update paths of all descendants."""
    child_dirs = await session.scalars(
            select(Directory)
            .where(qa(Directory.parent_id) == parent_id),
        )  # fmt: skip

    for child_dir in child_dirs:
        child_dir.path = [ou_to if p == ou_from else p for p in child_dir.path]
        await session.flush()
        await _update_descendants(
            session,
            child_dir.id,
            ou_from=ou_from,
            ou_to=ou_to,
        )


async def _update_attributes(
    session: AsyncSession,
    old_value: str,
    new_value: str,
) -> None:
    """Update attribute values during downgrade."""
    result = await session.execute(
            select(Attribute)
            .where(
                Attribute.value.ilike(f"%{old_value}%"),  # type: ignore
            ),
        )  # fmt: skip
    attributes = result.scalars().all()

    for attr in attributes:
        if attr.value and old_value in attr.value:
            attr.value = attr.value.replace(old_value, new_value)

    await session.flush()


def upgrade(container: AsyncContainer) -> None:
    """Upgrade: Rename 'services' container to 'System'."""

    async def _rename_services_to_system(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        service_dir = await session.scalar(
            select(Directory).where(
                qa(Directory.name) == "services",
                qa(Directory.is_system).is_(True),
            ),
        )
        if not service_dir:
            return
        ou_to = "ou=System"
        ou_from = "ou=services"

        service_dir.name = "System"
        service_dir.path = [
            ou_to if p == ou_from else p for p in service_dir.path
        ]

        await session.flush()
        await _update_descendants(
            session,
            service_dir.id,
            ou_from=ou_from,
            ou_to=ou_to,
        )

        await _update_attributes(session, ou_from, ou_to)
        await session.commit()

    op.run_async(_rename_services_to_system)


def downgrade(container: AsyncContainer) -> None:
    """Downgrade: Rename 'System' container back to 'services'."""

    async def _rename_system_to_services(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        system_dir = await session.scalar(
            select(Directory).where(
                qa(Directory.name) == "System",
                qa(Directory.is_system).is_(True),
            ),
        )
        if not system_dir:
            return
        ou_to = "ou=services"
        ou_from = "ou=System"

        system_dir.name = "services"
        system_dir.path = [
            ou_to if p == ou_from else p for p in system_dir.path
        ]

        await session.flush()
        await _update_descendants(
            session,
            system_dir.id,
            ou_from=ou_from,
            ou_to=ou_to,
        )

        await _update_attributes(
            session,
            ou_from,
            ou_to,
        )
        await session.commit()

    op.run_async(_rename_system_to_services)
