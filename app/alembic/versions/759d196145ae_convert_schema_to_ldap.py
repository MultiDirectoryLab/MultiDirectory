"""Migrate LDAP Schema data to Directory (like as LDAP).

Revision ID: 759d196145ae
Revises: 19d86e660cf2
Create Date: 2026-02-24 13:18:06.715730

"""

from alembic import op
from dishka import AsyncContainer, Scope
from entities_legacy import AttributeTypeLegacy
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from constants import ENTITY_TYPE_DTOS_V2
from entities import AccessControlEntry, Directory, EntityType
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
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.ldap_schema.object_class.object_class_use_case import (
    ObjectClassUseCase,
)
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "759d196145ae"
down_revision: None | str = "19d86e660cf2"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


# TODO переделай всё на юз кейсы
# мб можно делать отдельный юз кейс для миграций, и делать два метода:
# апгрейд и даунгрейд
def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""
    op.drop_constraint(
        op.f("AccessControlEntries_attributeTypeId_fkey"),
        "AccessControlEntries",
        type_="foreignkey",
    )

    async def _update_entity_types(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            entity_type_use_case = await cnt.get(EntityTypeUseCase)

        if not await get_base_directories(session):
            return

        for entity_type_dto in ENTITY_TYPE_DTOS_V2:
            await entity_type_use_case.create(entity_type_dto)

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

        obj_class_dtos = await object_class_use_case_legacy.get_all()
        for obj_class_dto in obj_class_dtos:
            obj_class_dto.attribute_types_may = [
                x.name  # type: ignore
                for x in obj_class_dto.attribute_types_may
            ]
            obj_class_dto.attribute_types_must = [
                x.name  # type: ignore
                for x in obj_class_dto.attribute_types_must
            ]
            await object_class_use_case.create(obj_class_dto)  # type: ignore

        await session.commit()

    async def _rebind_ace_attribute_types_to_directories(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        ace_rows_q = await session.execute(
            select(qa(AccessControlEntry.id), qa(AttributeTypeLegacy.name))
            .join(
                AttributeTypeLegacy,
                qa(AccessControlEntry.attribute_type_id)
                == qa(AttributeTypeLegacy.id),
            )
            .where(qa(AccessControlEntry.attribute_type_id).is_not(None)),
        )
        ace_rows = ace_rows_q.all()

        if ace_rows:
            attribute_names = {row.name for row in ace_rows}
            directory_rows_q = await session.execute(
                select(qa(Directory.name), qa(Directory.id))
                .join(
                    EntityType,
                    qa(EntityType.id) == qa(Directory.entity_type_id),
                )
                .where(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE)
                .where(qa(Directory.name).in_(attribute_names)),
            )
            directory_rows = directory_rows_q.all()
            directory_by_name = {row.name: row.id for row in directory_rows}

            updates = [
                {"ace_id": row.id, "directory_id": directory_by_name[row.name]}
                for row in ace_rows
                if row.name in directory_by_name
            ]
            if updates:
                for item in updates:
                    update_stmt = (
                        update(AccessControlEntry)
                        .where(qa(AccessControlEntry.id) == item["ace_id"])
                        .values(attribute_type_id=item["directory_id"])
                    )
                    await session.execute(update_stmt)

    op.run_async(_update_entity_types)
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


# TODO переделай всё на юз кейсы
# мб можно делать отдельный юз кейс для миграций, и делать два метода:
# апгрейд и даунгрейд
def downgrade(container: AsyncContainer) -> None:  # noqa: C901
    """Downgrade."""

    async def _rebind_ace_attribute_types_to_legacy(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        ace_rows_q = await session.execute(
            select(qa(AccessControlEntry.id), qa(Directory.name))
            .join(
                Directory,
                qa(AccessControlEntry.attribute_type_id) == qa(Directory.id),
            )
            .join(
                EntityType,
                qa(EntityType.id) == qa(Directory.entity_type_id),
            )
            .where(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE)
            .where(qa(AccessControlEntry.attribute_type_id).is_not(None)),
        )
        ace_rows = ace_rows_q.all()

        if ace_rows:
            attribute_names = {row.name for row in ace_rows}
            legacy_rows_q = await session.execute(
                select(
                    qa(AttributeTypeLegacy.name),
                    qa(AttributeTypeLegacy.id),
                ).where(
                    qa(AttributeTypeLegacy.name).in_(attribute_names),
                ),
            )
            legacy_rows = legacy_rows_q.all()
            legacy_by_name = {row.name: row.id for row in legacy_rows}

            updates = [
                {"ace_id": row.id, "legacy_id": legacy_by_name[row.name]}
                for row in ace_rows
                if row.name in legacy_by_name
            ]
            if updates:
                for item in updates:
                    update_stmt = (
                        update(AccessControlEntry)
                        .where(qa(AccessControlEntry.id) == item["ace_id"])
                        .values(attribute_type_id=item["legacy_id"])
                    )
                    await session.execute(update_stmt)

    async def _delete_ldap_object_classes(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            object_class_use_case_legacy = await cnt.get(
                ObjectClassUseCaseLegacy,
            )

        if not await get_base_directories(session):
            return

        entity_type_id = await session.scalar(
            select(qa(EntityType.id)).where(
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
            ),
        )
        if not entity_type_id:
            return

        obj_class_dtos = await object_class_use_case_legacy.get_all()
        obj_class_names = [dto.name for dto in obj_class_dtos]
        if not obj_class_names:
            return

        await session.execute(
            delete(Directory).where(
                qa(Directory.entity_type_id) == entity_type_id,
                qa(Directory.name).in_(obj_class_names),
            ),
        )
        await session.commit()

    async def _delete_ldap_attributes(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            attribute_type_use_case_legacy = await cnt.get(
                AttributeTypeUseCaseLegacy,
            )

        if not await get_base_directories(session):
            return

        entity_type_id = await session.scalar(
            select(qa(EntityType.id))
            .where(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE),
        )  # fmt: skip
        if not entity_type_id:
            return

        attr_type_dtos = await attribute_type_use_case_legacy.get_all()
        attr_type_names = [dto.name for dto in attr_type_dtos]
        if not attr_type_names:
            return

        await session.execute(
            delete(Directory).where(
                qa(Directory.entity_type_id) == entity_type_id,
                qa(Directory.name).in_(attr_type_names),
            ),
        )
        await session.commit()

    async def _delete_entity_types(connection: AsyncConnection) -> None:  # noqa: ARG001
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        entity_type_names = [dto.name for dto in ENTITY_TYPE_DTOS_V2]

        await session.execute(
            delete(EntityType)
            .where(qa(EntityType.name).in_(entity_type_names)),
        )  # fmt: skip
        await session.commit()

    op.drop_constraint(
        op.f("AccessControlEntries_directoryAttributeTypeId_fkey"),
        "AccessControlEntries",
        type_="foreignkey",
    )

    op.run_async(_rebind_ace_attribute_types_to_legacy)
    op.run_async(_delete_ldap_object_classes)
    op.run_async(_delete_ldap_attributes)
    op.run_async(_delete_entity_types)

    op.create_foreign_key(
        op.f("AccessControlEntries_attributeTypeId_fkey"),
        "AccessControlEntries",
        "AttributeTypes",
        ["attributeTypeId"],
        ["id"],
        ondelete="CASCADE",
    )
