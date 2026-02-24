"""Raw definition parser.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable

from entities_appendix import ObjectClass
from ldap3.protocol.rfc4512 import AttributeTypeInfo, ObjectClassInfo
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO


class RawDefinitionParser:
    """Parser for ObjectClass and AttributeType raw definition."""

    @staticmethod
    def _list_to_string(data: Iterable[str]) -> str | None:
        if not data:
            return None

        data = list(data)
        if len(data) == 1:
            return data[0]
        raise ValueError("Data is not a single element list")

    @staticmethod
    def _get_attribute_type_info(raw_definition: str) -> AttributeTypeInfo:
        tmp = AttributeTypeInfo.from_definition(definitions=[raw_definition])
        return RawDefinitionParser._list_to_string(tmp.values())

    @staticmethod
    def get_object_class_info(raw_definition: str) -> ObjectClassInfo:
        tmp = ObjectClassInfo.from_definition(definitions=[raw_definition])
        return RawDefinitionParser._list_to_string(tmp.values())

    @staticmethod  # TODO это надо уносить отсюда в DAO, и проверки делать только в DAO
    async def _is_all_attribute_types_exists(
        session: AsyncSession,
        names: list[str],
    ) -> bool:
        return True
        # TODO эту проверку в dao по созданию унести
        # query = await session.execute(
        #     select(AttributeType)
        #     .where(qa(AttributeType.name).in_(names)),
        # )  # fmt: skip
        # qwe = query.scalars().all()
        # print("\n\n\nSOSI")
        # print(len(qwe), qwe)
        # names = [n for n in names if "ms" not in n.lower()]
        # print(len(names), names)
        # return bool(len(list(qwe)) == len(names))

    @staticmethod
    def collect_attribute_type_dto_from_raw(
        raw_definition: str,
    ) -> AttributeTypeDTO:
        attribute_type_info = RawDefinitionParser._get_attribute_type_info(
            raw_definition=raw_definition,
        )

        return AttributeTypeDTO(
            oid=attribute_type_info.oid,
            name=RawDefinitionParser._list_to_string(attribute_type_info.name),  # type: ignore[arg-type]
            syntax=attribute_type_info.syntax,
            single_value=attribute_type_info.single_value,
            no_user_modification=attribute_type_info.no_user_modification,
            is_system=True,
            system_flags=0,
            is_included_anr=False,
        )

    @staticmethod  # TODO это надо уносить отсюда в DAO, и проверки делать только в DAO
    async def _get_object_class_by_name(
        object_class_name: str | None,
        session: AsyncSession,
    ) -> ObjectClass | None:
        if not object_class_name:
            return None

        dir_= await session.scalar(
            select(ObjectClass)
            .filter_by(name=object_class_name),
        )  # fmt: skip
        if not dir_:
            raise

        return dir_

    @staticmethod
    async def collect_object_class_dto_from_raw(
        session: AsyncSession,
        object_class_info: ObjectClassInfo,
    ) -> ObjectClassDTO:
        """Create Object Class by ObjectClassInfo."""
        # TODO эту проверку в dao по созданию унести
        # superior_object_class = (
        #     await RawDefinitionParser._get_object_class_by_name(
        #         superior_name,
        #         session,
        #     )
        # )

        # TODO эту проверку в dao по созданию унести
        # if not await RawDefinitionParser._is_all_attribute_types_exists(
        #     session,
        #     object_class_info.must_contain,
        # ):
        #     raise

        # TODO эту проверку в dao по созданию унести
        # if not await RawDefinitionParser._is_all_attribute_types_exists(
        #     session,
        #     object_class_info.may_contain,
        # ):
        #     raise

        object_class = ObjectClassDTO(
            oid=object_class_info.oid,
            name=RawDefinitionParser._list_to_string(object_class_info.name),  # type: ignore[arg-type]
            superior_name=RawDefinitionParser._list_to_string(object_class_info.superior),
            kind=object_class_info.kind,
            is_system=True,
            attribute_types_must=object_class_info.must_contain,
            attribute_types_may=object_class_info.may_contain,
        )  # fmt: skip

        return object_class
