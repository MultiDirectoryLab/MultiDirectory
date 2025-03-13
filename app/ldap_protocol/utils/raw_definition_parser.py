"""Raw definition parser.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap3.protocol.rfc4512 import AttributeTypeInfo, ObjectClassInfo
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AttributeType, ObjectClass


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
    def _get_object_class_info(raw_definition: str) -> ObjectClassInfo:
        tmp = ObjectClassInfo.from_definition(definitions=[raw_definition])
        return list(tmp.values())[0]

    @staticmethod
    async def _get_attribute_types_by_names(
        session: AsyncSession,
        names: list[str],
    ) -> list[AttributeType]:
        query = await session.execute(
            select(AttributeType)
            .where(AttributeType.name.in_(names))
        )  # fmt: skip
        return list(query.scalars().all())

    @staticmethod
    def create_attribute_type_by_raw(
        raw_definition: str,
    ) -> AttributeType:
        attribute_type_info = RawDefinitionParser._get_attribute_type_info(
            raw_definition=raw_definition
        )

        return AttributeType(
            oid=attribute_type_info.oid,
            name=RawDefinitionParser._list_to_string(attribute_type_info.name),
            syntax=attribute_type_info.syntax,
            single_value=attribute_type_info.single_value,
            no_user_modification=attribute_type_info.no_user_modification,
            is_system=False,
        )

    @staticmethod
    async def create_object_class_by_raw(
        session: AsyncSession,
        raw_definition: str,
    ) -> ObjectClass:
        object_class_info = RawDefinitionParser._get_object_class_info(
            raw_definition=raw_definition
        )

        object_class = ObjectClass(
            oid=object_class_info.oid,
            name=RawDefinitionParser._list_to_string(object_class_info.name),
            superior=RawDefinitionParser._list_to_string(
                object_class_info.superior
            ),
            kind=object_class_info.kind,
            is_system=False,
        )
        if object_class_info.must_contain:
            object_class.attribute_types_must.extend(
                await RawDefinitionParser._get_attribute_types_by_names(
                    session,
                    object_class_info.must_contain,
                )
            )
        if object_class_info.may_contain:
            object_class.attribute_types_may.extend(
                await RawDefinitionParser._get_attribute_types_by_names(
                    session,
                    object_class_info.may_contain,
                )
            )

        return object_class
