"""Attribute Type Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from abstract_service import AbstractService
from enums import AuthorizationRules
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.attribute_type_system_flags_use_case import (
    AttributeTypeSystemFlagsUseCase,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult


class AttributeTypeUseCase(AbstractService):
    """AttributeTypeUseCase."""

    def __init__(
        self,
        attribute_type_dao: AttributeTypeDAO,
        attribute_type_system_flags_use_case: AttributeTypeSystemFlagsUseCase,
        object_class_dao: ObjectClassDAO,
    ) -> None:
        """Init AttributeTypeUseCase."""
        self._attribute_type_dao = attribute_type_dao
        self._attribute_type_system_flags_use_case = (
            attribute_type_system_flags_use_case
        )
        self._object_class_dao = object_class_dao

    async def get(self, name: str) -> AttributeTypeDTO:
        """Get Attribute Type by name."""
        dto = await self._attribute_type_dao.get(name)
        dto.object_class_names = await self._object_class_dao.get_object_class_names_include_attribute_type(  # noqa: E501
            dto.name,
        )
        return dto

    async def get_all(self) -> list[AttributeTypeDTO]:
        """Get all Attribute Types."""
        return await self._attribute_type_dao.get_all()

    async def create(self, dto: AttributeTypeDTO) -> None:
        """Create Attribute Type."""
        await self._attribute_type_dao.create(dto)

    async def create_ldap(self, dto: AttributeTypeDTO) -> None:
        """Create Attribute Type."""
        await self._attribute_type_dao.create_ldap(dto)

    async def update(self, name: str, dto: AttributeTypeDTO) -> None:
        """Update Attribute Type."""
        await self._attribute_type_dao.update(name, dto)

    async def delete(self, name: str) -> None:
        """Delete Attribute Type."""
        await self._attribute_type_dao.delete(name)

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated Attribute Types."""
        return await self._attribute_type_dao.get_paginator(params)

    async def get_all_by_names(
        self,
        names: list[str] | set[str],
    ) -> list[AttributeTypeDTO]:
        """Get list of Attribute Types by names."""
        return await self._attribute_type_dao.get_all_by_names(names)

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Attribute Types by names."""
        return await self._attribute_type_dao.delete_all_by_names(names)

    async def is_attr_replicated(self, name: str) -> bool:
        """Check if attribute is replicated based on systemFlags."""
        dto = await self.get(name)
        return self._attribute_type_system_flags_use_case.is_attr_replicated(dto)  # noqa: E501  # fmt: skip

    async def set_attr_replication_flag(
        self,
        name: str,
        need_to_replicate: bool,
    ) -> None:
        """Set replication flag in systemFlags."""
        dto = await self.get(name)
        dto = self._attribute_type_system_flags_use_case.set_attr_replication_flag(  # noqa: E501
            dto,
            need_to_replicate,
        )
        await self._attribute_type_dao.update_sys_flags(dto.name, dto)

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        get.__name__: AuthorizationRules.ATTRIBUTE_TYPE_GET,
        create.__name__: AuthorizationRules.ATTRIBUTE_TYPE_CREATE,
        get_paginator.__name__: AuthorizationRules.ATTRIBUTE_TYPE_GET_PAGINATOR,  # noqa: E501
        update.__name__: AuthorizationRules.ATTRIBUTE_TYPE_UPDATE,
        delete_all_by_names.__name__: AuthorizationRules.ATTRIBUTE_TYPE_DELETE_ALL_BY_NAMES,  # noqa: E501
        set_attr_replication_flag.__name__: AuthorizationRules.ATTRIBUTE_TYPE_SET_ATTR_REPLICATION_FLAG,  # noqa: E501
    }
