"""Raw definition parser.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable

from ldap3.protocol.rfc4512 import AttributeTypeInfo, ObjectClassInfo

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

    @staticmethod
    def collect_attribute_type_dto_from_raw(
        raw_definition: str,
    ) -> AttributeTypeDTO:
        attribute_type_info = RawDefinitionParser._get_attribute_type_info(
            raw_definition=raw_definition,
        )

        name = RawDefinitionParser._list_to_string(attribute_type_info.name)
        if not name:
            raise ValueError("Attribute Type name is required")

        return AttributeTypeDTO(
            oid=attribute_type_info.oid,
            name=name,
            syntax=attribute_type_info.syntax,
            single_value=attribute_type_info.single_value,
            no_user_modification=attribute_type_info.no_user_modification,
            is_system=True,
            system_flags=0,
            is_included_anr=False,
        )

    @staticmethod
    async def collect_object_class_dto_from_info(
        object_class_info: ObjectClassInfo,
    ) -> ObjectClassDTO:
        """Create Object Class by ObjectClassInfo."""
        name = RawDefinitionParser._list_to_string(object_class_info.name)
        if not name:
            raise ValueError("Attribute Type name is required")

        return ObjectClassDTO(
            oid=object_class_info.oid,
            name=name,
            superior_name=RawDefinitionParser._list_to_string(object_class_info.superior),
            kind=object_class_info.kind,
            is_system=True,
            attribute_types_must=object_class_info.must_contain,
            attribute_types_may=object_class_info.may_contain,
        )  # fmt: skip
