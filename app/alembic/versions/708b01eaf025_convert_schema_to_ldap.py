"""Migrate LDAP Schema data to Directory (like as LDAP).

Revision ID: 759d196145ae
Revises: 19d86e660cf2
Create Date: 2026-02-24 13:18:06.715730

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from constants import CONFIGURATION_DIR_NAME, ENTITY_TYPE_DTOS_V2
from enums import EntityTypeNames
from extra.alembic_utils import temporary_stub_column
from ldap_protocol.ldap_schema._legacy.attribute_type.attribute_type_use_case import (  # noqa: E501
    AttributeTypeUseCaseLegacy,
)
from ldap_protocol.ldap_schema._legacy.object_class.object_class_use_case import (  # noqa: E501
    ObjectClassUseCaseLegacy,
)
from ldap_protocol.ldap_schema.attribute_type.attribute_type_use_case import (
    AttributeTypeUseCase,
)
from ldap_protocol.ldap_schema.directory_create_use_case import (
    DirectoryCreateUseCase,
)
from ldap_protocol.ldap_schema.dto import AttributeDTO, CreateDirDTO
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.ldap_schema.object_class.object_class_use_case import (
    ObjectClassUseCase,
)
from ldap_protocol.roles.migrations_ace_dao import (
    AccessControlEntryAttributeTypeRemapDAO,
)
from ldap_protocol.utils.queries import get_base_directories

# revision identifiers, used by Alembic.
revision: None | str = "708b01eaf025"
down_revision: None | str = "df4287898910"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


@temporary_stub_column(
    "AccessControlEntries",
    "attribute_type_name",
    sa.String(),
)
def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""

    async def _update_entity_types(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            entity_type_use_case = await cnt.get(EntityTypeUseCase)

        if not await get_base_directories(session):
            return

        for entity_type_dto in ENTITY_TYPE_DTOS_V2:
            await entity_type_use_case.create_not_safe(entity_type_dto)

        await session.commit()

    async def _create_ldap_configuration_directory(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            directory_create_use_case = await cnt.get(DirectoryCreateUseCase)

        base_dirs = await get_base_directories(session)
        if not base_dirs:
            return

        _dto = CreateDirDTO(
            name=CONFIGURATION_DIR_NAME,
            entity_type_name=EntityTypeNames.CONFIGURATION,
            attributes=(
                AttributeDTO(
                    name="objectClass",
                    values=["top", "container", "configuration"],
                ),
            ),
            is_system=True,
        )

        await directory_create_use_case.create_dir(
            dto=_dto,
            parent_dir=base_dirs[0],
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
            obj_cls_use_case_legacy = await cnt.get(ObjectClassUseCaseLegacy)
            object_class_use_case = await cnt.get(ObjectClassUseCase)

        if not await get_base_directories(session):
            return

        obj_class_dtos = await obj_cls_use_case_legacy.get_all()
        for obj_class_dto in obj_class_dtos:
            obj_class_dto.attribute_types_may = [
                _.name  # type: ignore
                for _ in obj_class_dto.attribute_types_may
            ]
            obj_class_dto.attribute_types_must = [
                _.name  # type: ignore
                for _ in obj_class_dto.attribute_types_must
            ]
            await object_class_use_case.create(obj_class_dto)  # type: ignore

        await session.commit()

    async def _rebind_ace_attribute_types_to_directories(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            ace_dao = await cnt.get(AccessControlEntryAttributeTypeRemapDAO)

        if not await get_base_directories(session):
            return

        await ace_dao.upgrade()
        await session.commit()

    op.drop_constraint(
        op.f("AccessControlEntries_attributeTypeId_fkey"),
        "AccessControlEntries",
        type_="foreignkey",
    )

    op.run_async(_update_entity_types)
    op.run_async(_create_ldap_configuration_directory)
    op.run_async(_create_ldap_attributes)
    op.run_async(_create_ldap_object_classes)
    op.run_async(_rebind_ace_attribute_types_to_directories)

    op.create_foreign_key(
        op.f("AccessControlEntries_directoryAttributeTypeId_fkey"),
        "AccessControlEntries",
        "Directory",
        ["attributeTypeId"],
        ["id"],
        ondelete="CASCADE",
    )


@temporary_stub_column(
    "AccessControlEntries",
    "attribute_type_name",
    sa.String(),
)
def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""

    async def _rebind_ace_attribute_types_to_legacy(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            ace_dao = await cnt.get(AccessControlEntryAttributeTypeRemapDAO)

        if not await get_base_directories(session):
            return

        await ace_dao.downgrade()
        await session.commit()

    async def _delete_ldap_attributes(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            attribute_type_use_case_legacy = await cnt.get(AttributeTypeUseCaseLegacy)  # noqa: E501  # fmt: skip

        if not await get_base_directories(session):
            return

        await attribute_type_use_case_legacy.delete_all_dirs()
        await session.commit()

    async def _delete_ldap_object_classes(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            obj_cls_use_case_legacy = await cnt.get(ObjectClassUseCaseLegacy)

        if not await get_base_directories(session):
            return

        await obj_cls_use_case_legacy.delete_all_dirs()
        await session.commit()

    async def _delete_ldap_configuration_directory(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            directory_create_use_case = await cnt.get(DirectoryCreateUseCase)

        if not await get_base_directories(session):
            return

        await directory_create_use_case.delete_configuration_dir()
        await session.commit()

    async def _delete_entity_types(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            entity_type_use_case = await cnt.get(EntityTypeUseCase)

        if not await get_base_directories(session):
            return

        entity_type_names = [dto.name for dto in ENTITY_TYPE_DTOS_V2]

        await entity_type_use_case.delete_all_by_names_not_safe(
            entity_type_names,
        )
        await session.commit()

    op.drop_constraint(
        op.f("AccessControlEntries_directoryAttributeTypeId_fkey"),
        "AccessControlEntries",
        type_="foreignkey",
    )

    op.run_async(_rebind_ace_attribute_types_to_legacy)
    op.run_async(_delete_ldap_attributes)
    op.run_async(_delete_ldap_object_classes)
    op.run_async(_delete_ldap_configuration_directory)
    op.run_async(_delete_entity_types)

    op.create_foreign_key(
        op.f("AccessControlEntries_attributeTypeId_fkey"),
        "AccessControlEntries",
        "AttributeTypes",
        ["attributeTypeId"],
        ["id"],
        ondelete="CASCADE",
    )
