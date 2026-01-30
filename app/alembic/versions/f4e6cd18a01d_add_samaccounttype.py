"""Add sAMAccountType to existing user/group/computer entries.

Revision ID: f4e6cd18a01d
Revises: 379fce54fb08
Create Date: 2026-01-30 13:08:26.299158

"""

from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import selectinload

from entities import Attribute, Directory, EntityType
from enums import EntityTypeNames, SamAccountType
from repo.pg.tables import queryable_attr as qa

revision: None | str = "f4e6cd18a01d"
down_revision: None | str = "379fce54fb08"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None

_SAM_ACCOUNT_TYPE_ATTR = "sAMAccountType"
_SECURITY_PRINCIPAL_TYPES = (
    EntityTypeNames.USER,
    EntityTypeNames.GROUP,
    EntityTypeNames.COMPUTER,
)
_ENTITY_TO_SAM: dict[str, SamAccountType] = {
    EntityTypeNames.USER: SamAccountType.SAM_USER_OBJECT,
    EntityTypeNames.GROUP: SamAccountType.SAM_GROUP_OBJECT,
    EntityTypeNames.COMPUTER: SamAccountType.SAM_MACHINE_ACCOUNT,
}


def upgrade(container: AsyncContainer) -> None:
    """Add sAMAccountType attributes for user/group/computer."""

    async def _add_samaccounttype(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        entity_types = await session.scalars(
            select(EntityType).where(
                qa(EntityType.name).in_(_SECURITY_PRINCIPAL_TYPES),
            ),
        )
        entity_type_ids = [et.id for et in entity_types]
        if not entity_type_ids:
            return

        has_sam = select(qa(Attribute.directory_id)).where(
            qa(Attribute.name).ilike(_SAM_ACCOUNT_TYPE_ATTR.lower()),
        )
        dirs_without_sam = await session.scalars(
            select(Directory)
            .where(
                qa(Directory.entity_type_id).in_(entity_type_ids),
                ~qa(Directory.id).in_(has_sam),
            )
            .options(selectinload(qa(Directory.entity_type))),
        )

        for directory in dirs_without_sam:
            if not directory.entity_type:
                continue
            sam_value = _ENTITY_TO_SAM.get(directory.entity_type.name)
            if sam_value is None:
                continue

            session.add(
                Attribute(
                    name=_SAM_ACCOUNT_TYPE_ATTR,
                    value=str(sam_value),
                    directory_id=directory.id,
                ),
            )

        await session.commit()

    op.run_async(_add_samaccounttype)


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""
