"""Add Contact objectClass and mailRecipient to LDAP schema.

Revision ID: c5a9b3f2e8d7
Revises: 8164b4a9e1f1, f1abf7ef2443
Create Date: 2026-01-19 12:00:00.000000

"""

from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from application.entities import EntityType
from enums import EntityTypeNames
from application.ldap_schema.dto import EntityTypeDTO
from application.ldap_schema.entity_type_use_case import EntityTypeUseCase
from application.utils.queries import get_base_directories
from infrastructure.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision = "c5a9b3f2e8d7"
down_revision = "71e642808369"
branch_labels: None | str = None
depends_on: None | str = None


def upgrade(container: AsyncContainer) -> None:
    """Add Contact objectClass and mailRecipient to LDAP schema."""

    async def _create_entity_type(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Create Contact Entity Type."""
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            entity_type_use_case = await cnt.get(EntityTypeUseCase)

        if not await get_base_directories(session):
            return

        await entity_type_use_case.create(
            EntityTypeDTO(
                name=EntityTypeNames.CONTACT,
                object_class_names=[
                    "top",
                    "person",
                    "organizationalPerson",
                    "contact",
                    "mailRecipient",
                ],
                is_system=True,
            ),
        )

        await session.commit()

    op.run_async(_create_entity_type)


def downgrade(container: AsyncContainer) -> None:
    """Remove Contact objectClass and mailRecipient from LDAP schema."""

    async def _delete_entity_type(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Delete Contact Entity Type."""
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        await session.execute(
            delete(EntityType).where(
                qa(EntityType.name) == EntityTypeNames.CONTACT,
            ),
        )

        await session.commit()

    op.run_async(_delete_entity_type)
