"""Rename services container to System for AD compatibility.

Revision ID: a1b2c3d4e5f6
Revises: 6c858cc05da7
Create Date: 2026-01-13 12:00:00.000000

"""

from alembic import op
from dishka import AsyncContainer
from sqlalchemy import and_, exists, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Attribute, Directory
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "a1b2c3d4e5f6"
down_revision: None | str = "6c858cc05da7"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Upgrade: Rename 'services' container to 'System'."""

    async def _update_descendants(
        session: AsyncSession,
        parent_id: int,
    ) -> None:
        """Recursively update paths of all descendants."""
        child_dirs = await session.scalars(
            select(Directory)
            .where(qa(Directory.parent_id) == parent_id),
        )  # fmt: skip

        for child_dir in child_dirs:
            child_dir.path = [
                "ou=System" if p == "ou=services" else p
                for p in child_dir.path
            ]
            await session.flush()
            await _update_descendants(session, child_dir.id)

    async def _update_attributes(
        session: AsyncSession,
        old_value: str,
        new_value: str,
    ) -> None:
        """Update attribute values containing old DN."""
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

    async def _rename_services_to_system(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        try:
            base_directories = await get_base_directories(session)
            if not base_directories:
                await session.commit()
                return

            service_dirs = await session.scalars(
                select(Directory).where(qa(Directory.name) == "services"),
            )

            for service_dir in service_dirs:
                system_exists = await session.scalar(
                    select(exists(Directory))
                    .where(
                        and_(
                            qa(Directory.name) == "System",
                            qa(Directory.parent_id) == service_dir.parent_id,
                        ),
                    ),
                )  # fmt: skip

                if system_exists:
                    continue

                service_dir.name = "System"
                service_dir.path = [
                    "ou=System" if p == "ou=services" else p
                    for p in service_dir.path
                ]

                await session.flush()
                await _update_descendants(session, service_dir.id)

            await _update_attributes(session, "ou=services", "ou=System")
            await session.commit()

        except Exception:
            await session.rollback()
            raise

    op.run_async(_rename_services_to_system)


def downgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Downgrade: Rename 'System' container back to 'services'."""

    async def _update_descendants_downgrade(
        session: AsyncSession,
        parent_id: int,
    ) -> None:
        """Recursively update paths of all descendants."""
        child_dirs = await session.scalars(
            select(Directory)
            .where(qa(Directory.parent_id) == parent_id),
        )  # fmt: skip

        for child_dir in child_dirs:
            child_dir.path = [
                "ou=services" if p == "ou=System" else p
                for p in child_dir.path
            ]
            await session.flush()
            await _update_descendants_downgrade(session, child_dir.id)

    async def _update_attributes_downgrade(
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

    async def _rename_system_to_services(connection: AsyncConnection) -> None:
        session = AsyncSession(bind=connection)
        await session.begin()

        try:
            base_directories = await get_base_directories(session)
            if not base_directories:
                await session.commit()
                return

            system_dirs = await session.scalars(
                select(Directory).where(qa(Directory.name) == "System"),
            )

            for system_dir in system_dirs:
                system_dir.name = "services"
                system_dir.path = [
                    "ou=services" if p == "ou=System" else p
                    for p in system_dir.path
                ]

                await session.flush()
                await _update_descendants_downgrade(session, system_dir.id)

            await _update_attributes_downgrade(
                session,
                "ou=System",
                "ou=services",
            )
            await session.commit()

        except Exception:
            await session.rollback()
            raise

    op.run_async(_rename_system_to_services)
