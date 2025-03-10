"""LDAP3 parser.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap3.protocol.rfc4512 import AttributeTypeInfo, ObjectClassInfo
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AttributeType, ObjectClass


class Ldap3Parser:
    """LDAP3 parser."""

    @classmethod
    def _list_to_string(cls, data: list[str]) -> str | None:
        if not data:
            return None
        if len(data) == 1:
            return data[0]
        raise ValueError("Data is not a single element list")

    @classmethod
    def _get_attribute_type_info(
        cls,
        raw_definition: str,
    ) -> AttributeTypeInfo:
        tmp = AttributeTypeInfo.from_definition(definitions=[raw_definition])
        return list(tmp.values())[0]

    @classmethod
    def _get_object_class_info(cls, raw_definition: str) -> ObjectClassInfo:
        tmp = ObjectClassInfo.from_definition(definitions=[raw_definition])
        return list(tmp.values())[0]

    @classmethod
    async def _get_attribute_types(
        cls,
        session: AsyncSession,
        names: list[str],
    ) -> list[AttributeType]:
        query = await session.execute(
            select(AttributeType)
            .where(AttributeType.name.in_(names))
        )  # fmt: skip
        return list(query.scalars().all())

    @classmethod
    def get_attribute_type(cls, raw_definition: str) -> AttributeType:
        attribute_type_info: AttributeTypeInfo = cls._get_attribute_type_info(
            raw_definition=raw_definition
        )

        return AttributeType(
            oid=attribute_type_info.oid,
            name=cls._list_to_string(attribute_type_info.name),
            syntax=attribute_type_info.syntax,
            single_value=attribute_type_info.single_value,
            no_user_modification=attribute_type_info.no_user_modification,
            is_system=False,
        )

    @classmethod
    async def get_object_class(
        cls,
        session: AsyncSession,
        raw_definition: str,
    ) -> ObjectClass:
        object_class_info: ObjectClassInfo = cls._get_object_class_info(
            raw_definition=raw_definition
        )

        object_class = ObjectClass(
            oid=object_class_info.oid,
            name=cls._list_to_string(object_class_info.name),
            superior=cls._list_to_string(object_class_info.superior),
            kind=object_class_info.kind,
            is_system=False,
        )
        if object_class_info.must_contain:
            object_class.attribute_types_must.extend(
                await cls._get_attribute_types(
                    session=session,
                    names=object_class_info.must_contain,
                )
            )
        if object_class_info.may_contain:
            object_class.attribute_types_may.extend(
                await cls._get_attribute_types(
                    session=session,
                    names=object_class_info.may_contain,
                )
            )

        return object_class
