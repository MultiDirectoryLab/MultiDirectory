"""empty message.

Revision ID: 759d196145ae
Revises: 19d86e660cf2
Create Date: 2026-02-24 13:18:06.715730

"""

from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from constants import ENTITY_TYPE_DATAS
from enums import EntityTypeNames
from ldap_protocol.ldap_schema._legacy.attribute_type.attribute_type_use_case import (  # noqa: E501
    AttributeTypeUseCaseLegacy,
)
from ldap_protocol.ldap_schema._legacy.object_class.object_class_use_case import (  # noqa: E501
    ObjectClassUseCaseLegacy,
)
from ldap_protocol.ldap_schema.attribute_type.attribute_type_use_case import (
    AttributeTypeUseCase,
)
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.ldap_schema.object_class.object_class_use_case import (
    ObjectClassUseCase,
)
from ldap_protocol.utils.queries import get_base_directories

# revision identifiers, used by Alembic.
revision: None | str = "759d196145ae"
down_revision: None | str = "19d86e660cf2"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""

    async def _update_entity_types(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            entity_type_use_case = await cnt.get(EntityTypeUseCase)

        if not await get_base_directories(session):
            return

        for entity_type_data in ENTITY_TYPE_DATAS:
            if entity_type_data["name"] in (
                EntityTypeNames.CONFIGURATION,
                EntityTypeNames.ATTRIBUTE_TYPE,
                EntityTypeNames.OBJECT_CLASS,
            ):
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
            attribute_type_use_case_legacy = await cnt.get(AttributeTypeUseCaseLegacy)  # noqa: E501  # fmt: skip

        if not await get_base_directories(session):
            return

        attr_type_dtos = await attribute_type_use_case_legacy.get_all()
        for attr_type_dto in attr_type_dtos:
            await attribute_type_use_case.create(attr_type_dto)

        await session.commit()

    async def _create_ldap_object_classes(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            object_class_use_case_legacy = await cnt.get(
                ObjectClassUseCaseLegacy,
            )
            object_class_use_case = await cnt.get(ObjectClassUseCase)

        if not await get_base_directories(session):
            return

        ocs = await object_class_use_case_legacy.get_all()
        for _oc in ocs:
            _oc.attribute_types_may = [x.name for x in _oc.attribute_types_may]  # type: ignore
            _oc.attribute_types_must = [
                x.name  # type: ignore
                for x in _oc.attribute_types_must
            ]
            await object_class_use_case.create(_oc)  # type: ignore

        await session.commit()

    op.run_async(_update_entity_types)
    op.run_async(_create_ldap_attributes)
    op.run_async(_create_ldap_object_classes)


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""
