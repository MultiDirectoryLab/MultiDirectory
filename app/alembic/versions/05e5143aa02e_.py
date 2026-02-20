"""empty message.

Revision ID: 05e5143aa02e
Revises: 2dadf40c026a
Create Date: 2026-02-13 09:37:39.506101

"""

from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from constants import ENTITY_TYPE_DATAS
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.appendix.attribute_type.use_case import (
    AttributeTypeUseCaseDeprecated,
)
from ldap_protocol.ldap_schema.attribute_type_use_case import (
    AttributeTypeUseCase,
)
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.ldap_schema.object_class_use_case import ObjectClassUseCase
from ldap_protocol.utils.queries import get_base_directories

# revision identifiers, used by Alembic.
revision: None | str = "05e5143aa02e"
down_revision: None | str = "2dadf40c026a"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None

get_base_directories


def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""

    async def _update_entity_types(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            entity_type_use_case = await cnt.get(EntityTypeUseCase)

        # if not await get_base_directories(session):
        #     return

        for entity_type_data in ENTITY_TYPE_DATAS:
            if entity_type_data["name"] in (
                EntityTypeNames.CONFIGURATION,
                EntityTypeNames.ATTRIBUTE_TYPE,
                EntityTypeNames.OBJECT_CLASS,
            ) and not await entity_type_use_case.get(entity_type_data["name"]):
                await entity_type_use_case.create(
                    EntityTypeDTO[None](
                        name=entity_type_data["name"],
                        object_class_names=entity_type_data[
                            "object_class_names"
                        ],
                        is_system=True,
                    ),
                )

        await session.commit()

    async def _create_ldap_attributes(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            attribute_type_use_case = await cnt.get(AttributeTypeUseCase)
            attribute_type_use_case_deprecated = await cnt.get(
                AttributeTypeUseCaseDeprecated,
            )

        if not await get_base_directories(session):
            return

        ats = await attribute_type_use_case_deprecated.get_all_deprecated()
        for _at in ats:
            await attribute_type_use_case.create(_at)

        await session.commit()

    async def _create_ldap_object_classes(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            object_class_use_case = await cnt.get(ObjectClassUseCase)

        if not await get_base_directories(session):
            return

        ocs = await object_class_use_case.get_all()
        for _oc in ocs:
            await object_class_use_case.create_ldap(_oc)  # type: ignore

        await session.commit()

    # op.run_async(_update_entity_types)  # TODO раскоментить
    op.run_async(_create_ldap_attributes)
    # op.run_async(_create_ldap_object_classes)   # noqa: ERA001


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""
