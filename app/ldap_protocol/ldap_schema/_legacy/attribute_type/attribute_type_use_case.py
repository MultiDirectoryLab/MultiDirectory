"""Attribute Type Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar, Sequence

from entities_legacy import AttributeTypeLegacy

from abstract_service import AbstractService
from enums import AuthorizationRules
from ldap_protocol.ldap_schema._legacy.attribute_type.attribute_type_dao import (  # noqa: E501
    AttributeTypeDAOLegacy,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO


class AttributeTypeUseCaseLegacy(AbstractService):
    """AttributeTypeUseCase."""

    __attribute_type_dao_legacy: AttributeTypeDAOLegacy

    def __init__(
        self,
        attribute_type_dao_legacy: AttributeTypeDAOLegacy,
    ) -> None:
        """Init AttributeTypeUseCase."""
        self.__attribute_type_dao_legacy = attribute_type_dao_legacy

    async def get(self, name: str) -> AttributeTypeDTO[int]:
        """Get Attribute Type by name."""
        dto = await self.__attribute_type_dao_legacy.get(name)
        dto.object_class_names = await self.__attribute_type_dao_legacy.get_object_class_names_include_attribute_type(dto.name)  # noqa: E501  # fmt: skip
        return dto

    async def get_all(self) -> list[AttributeTypeDTO[int]]:
        """Get all Attribute Types."""
        return await self.__attribute_type_dao_legacy.get_all()

    async def create(self, dto: AttributeTypeDTO[None]) -> None:
        """Create Attribute Type."""
        await self.__attribute_type_dao_legacy.create(dto)

    async def delete_table(self) -> None:
        await self.__attribute_type_dao_legacy.delete_table()

    async def zero_all_replicated_flags(self) -> None:
        """Set replication flag to False for all Attribute Types."""
        await self.__attribute_type_dao_legacy.zero_all_replicated_flags()

    async def set_false_replication_flag(
        self,
        names: tuple[str, ...],
    ) -> None:
        """Set replication flag in systemFlags."""
        await self.__attribute_type_dao_legacy.set_false_replication_flag(
            names,
        )

    async def mark_anr_included_by_attr_names(
        self,
        names: tuple[str, ...],
    ) -> list[str]:
        """Update Attribute Types and return updated DTOs."""
        return await self.__attribute_type_dao_legacy.mark_anr_included_by_attr_names(  # noqa: E501
            names,
        )

    async def false_all_is_included_anr(self) -> None:
        """Set is_included_anr to False for all Attribute Types."""
        await self.__attribute_type_dao_legacy.false_all_is_included_anr()

    async def get_all_raw_by_names(
        self,
        names: list[str],
    ) -> Sequence[AttributeTypeLegacy]:
        """Get list of Attribute Types by names."""
        return await self.__attribute_type_dao_legacy.get_all_raw_by_names(
            names,
        )

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {}
