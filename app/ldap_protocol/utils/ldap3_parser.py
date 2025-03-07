"""LDAP3 parser.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap3.protocol.rfc4512 import AttributeTypeInfo, ObjectClassInfo

from models import AttributeType


class Ldap3Parser:
    """LDAP3 parser."""

    @staticmethod
    def _list_to_string(data: list[str]) -> str | None:
        res = None
        if data:
            if len(data) == 1:
                res = data[0]
            else:
                raise ValueError("Data is not a single element list")
        return res

    @staticmethod
    def _get_attribute_type_info(raw_attribute_type: str) -> AttributeTypeInfo:
        """Get attribute type info."""
        tmp = AttributeTypeInfo.from_definition(
            definitions=[raw_attribute_type]
        )
        return list(tmp.values())[0]

    @staticmethod
    def _get_object_class_info(raw_object_class: str) -> ObjectClassInfo:
        """Get object class info."""
        tmp = ObjectClassInfo.from_definition(definitions=[raw_object_class])
        return list(tmp.values())[0]

    def get_attribute_type(self):
        attribute_type_info: AttributeTypeInfo = _get_attribute_type_info(self)

        AttributeType(
            oid=attribute_type_info.oid,
            name=_list_to_string(attribute_type_info.name),
            syntax=attribute_type_info.syntax,
            single_value=attribute_type_info.single_value,
            no_user_modification=attribute_type_info.no_user_modification,
            is_system=True,
        )
