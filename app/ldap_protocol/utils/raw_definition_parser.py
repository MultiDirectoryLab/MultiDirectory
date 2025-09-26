"""Raw definition parser.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap3.protocol.rfc4512 import AttributeTypeInfo, ObjectClassInfo
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AttributeType, ObjectClass, attribute_types_table


class RawDefinitionParser:
    """Parser for ObjectClass and AttributeType raw definition."""

    @staticmethod
    def _list_to_string(data: list[str]) -> str | None:
        if not data:
            return None
        if len(data) == 1:
            return data[0]
        raise ValueError("Data is not a single element list")

    @staticmethod
    def _get_attribute_type_info(raw_definition: str) -> AttributeTypeInfo:
        tmp = AttributeTypeInfo.from_definition(definitions=[raw_definition])
        return list(tmp.values())[0]

    @staticmethod
    def get_object_class_info(raw_definition: str) -> ObjectClassInfo:
        tmp = ObjectClassInfo.from_definition(definitions=[raw_definition])
        return list(tmp.values())[0]

    @staticmethod
    async def _get_attribute_types_by_names(
        session: AsyncSession,
        names: list[str],
    ) -> list[AttributeType]:
        query = await session.execute(
            select(AttributeType)
            .where(attribute_types_table.c.name.in_(names)),
        )  # fmt: skip
        return list(query.scalars().all())

    @staticmethod
    def create_attribute_type_by_raw(
        raw_definition: str,
    ) -> AttributeType:
        attribute_type_info = RawDefinitionParser._get_attribute_type_info(
            raw_definition=raw_definition,
        )

        return AttributeType(
            oid=attribute_type_info.oid,
            name=RawDefinitionParser._list_to_string(attribute_type_info.name),  # type: ignore[arg-type]
            syntax=attribute_type_info.syntax,
            single_value=attribute_type_info.single_value,
            no_user_modification=attribute_type_info.no_user_modification,
            is_system=True,
        )

    @staticmethod
    async def _get_object_class_by_name(
        object_class_name: str | None,
        session: AsyncSession,
    ) -> ObjectClass | None:
        if not object_class_name:
            return None

        return await session.scalar(
            select(ObjectClass)
            .filter_by(name=object_class_name),
        )  # fmt: skip

    @staticmethod
    async def create_object_class_by_info(
        session: AsyncSession,
        object_class_info: ObjectClassInfo,
    ) -> ObjectClass:
        """Create Object Class by ObjectClassInfo."""
        superior_name = RawDefinitionParser._list_to_string(
            object_class_info.superior,
        )

        superior_object_class = (
            await RawDefinitionParser._get_object_class_by_name(
                superior_name,
                session,
            )
        )

        object_class = ObjectClass(
            oid=object_class_info.oid,
            name=RawDefinitionParser._list_to_string(object_class_info.name),  # type: ignore[arg-type]
            superior=superior_object_class,
            kind=object_class_info.kind,
            is_system=True,
        )
        if object_class_info.must_contain:
            object_class.attribute_types_must.extend(
                await RawDefinitionParser._get_attribute_types_by_names(
                    session,
                    object_class_info.must_contain,
                ),
            )
        if object_class_info.may_contain:
            object_class.attribute_types_may.extend(
                await RawDefinitionParser._get_attribute_types_by_names(
                    session,
                    object_class_info.may_contain,
                ),
            )

        return object_class
