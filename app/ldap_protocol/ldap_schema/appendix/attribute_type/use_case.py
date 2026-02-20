"""Attribute Type Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar, Iterable, Sequence

from abstract_service import AbstractService
from entities import AttributeType
from enums import AuthorizationRules
from ldap_protocol.ldap_schema.appendix.attribute_type.dao import (
    AttributeTypeDAODeprecated,
)
from ldap_protocol.ldap_schema.attribute_type_system_flags_use_case import (
    AttributeTypeSystemFlagsUseCase,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO


class AttributeTypeUseCaseDeprecated(AbstractService):
    """AttributeTypeUseCase."""

    def __init__(
        self,
        attribute_type_dao_deprecated: AttributeTypeDAODeprecated,
        attribute_type_system_flags_use_case: AttributeTypeSystemFlagsUseCase,
        object_class_dao: ObjectClassDAO,
    ) -> None:
        """Init AttributeTypeUseCase."""
        self._attribute_type_dao = attribute_type_dao_deprecated
        self._attribute_type_system_flags_use_case = (
            attribute_type_system_flags_use_case
        )
        self._object_class_dao = object_class_dao

    async def get_deprecated(self, name: str) -> AttributeTypeDTO:
        """Get Attribute Type by name."""
        dto = await self._attribute_type_dao.get_deprecated(name)
        dto.object_class_names = await self._object_class_dao.get_object_class_names_include_attribute_type(  # noqa: E501
            dto.name,
        )
        return dto

    async def get_all_deprecated(self) -> list[AttributeTypeDTO]:
        """Get all Attribute Types."""
        return await self._attribute_type_dao.get_all_deprecated()

    async def create_deprecated(self, dto: AttributeTypeDTO[None]) -> None:
        """Create Attribute Type."""
        await self._attribute_type_dao.create_deprecated(dto)

    async def update_deprecated(
        self,
        name: str,
        dto: AttributeTypeDTO,
    ) -> None:
        """Update Attribute Type."""
        await self._attribute_type_dao.update_deprecated(name, dto)

    async def update_and_get_migration_f24ed_deprecated(
        self,
        names: Iterable[str],
    ) -> list[AttributeTypeDTO]:
        """Update Attribute Types and return updated DTOs."""
        attribute_types = (
            await self._attribute_type_dao.get_all_by_names_deprecated(
                list(names),
            )
        )
        for at in attribute_types:
            at.is_included_anr = True
            await self._attribute_type_dao.update_deprecated(at.name, at)
        return attribute_types

    async def zero_all_replicated_flags_deprecated(self) -> None:
        """Set replication flag to False for all Attribute Types."""
        attribute_types = await self._attribute_type_dao.get_all_deprecated()
        for at in attribute_types:
            at = self._attribute_type_system_flags_use_case.set_attr_replication_flag(  # noqa: E501
                at,
                need_to_replicate=True,
            )
            await self._attribute_type_dao.update_sys_flags_deprecated(
                at.name,
                at,
            )

    async def false_all_is_included_anr_deprecated(self) -> None:
        """Set is_included_anr to False for all Attribute Types."""
        attribute_types = await self._attribute_type_dao.get_all_deprecated()
        for at in attribute_types:
            at.is_included_anr = False
            await self._attribute_type_dao.update_deprecated(at.name, at)

    async def get_all_raw_by_names_deprecated(
        self,
        names: list[str] | set[str],
    ) -> Sequence[AttributeType]:
        """Get list of Attribute Types by names."""
        return await self._attribute_type_dao.get_all_raw_by_names_deprecated(
            names,
        )

    async def set_attr_replication_flag_deprecated(
        self,
        name: str,
        need_to_replicate: bool,
    ) -> None:
        """Set replication flag in systemFlags."""
        dto = await self.get_deprecated(name)
        dto = self._attribute_type_system_flags_use_case.set_attr_replication_flag(  # noqa: E501
            dto,
            need_to_replicate,
        )
        await self._attribute_type_dao.update_sys_flags_deprecated(
            dto.name,
            dto,
        )

    async def get_all_by_names_deprecated(
        self,
        names: list[str] | set[str],
    ) -> list[AttributeTypeDTO]:
        """Get list of Attribute Types by names."""
        return await self._attribute_type_dao.get_all_by_names_deprecated(
            names,
        )

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        set_attr_replication_flag_deprecated.__name__: AuthorizationRules.ATTRIBUTE_TYPE_SET_ATTR_REPLICATION_FLAG,  # noqa: E501
    }
