"""Attribute Type Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abstract_dao import AbstractService
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.dto import (
    AttributeTypeDTO,
    AttributeTypeExtendedDTO,
)
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult


class AttributeTypeUseCase(AbstractService):
    """AttributeTypeUseCase."""

    def __init__(
        self,
        attribute_type_dao: AttributeTypeDAO,
        object_class_dao: ObjectClassDAO,
    ) -> None:
        """Init AttributeTypeUseCase."""
        self._attribute_type_dao = attribute_type_dao
        self._object_class_dao = object_class_dao

    async def get(self, _id: str) -> AttributeTypeExtendedDTO:
        """Get Extended Attribute Type by id."""
        dto = await self._attribute_type_dao.get(_id)
        extended_dto = AttributeTypeExtendedDTO(**dto.__dict__)
        extended_dto.object_class_names = await self._object_class_dao.get_object_class_names_include_attribute_type(  # noqa: E501
            dto.name,
        )
        return extended_dto

    async def get_all(self) -> list[AttributeTypeDTO]:
        """Get all Attribute Types."""
        return await self._attribute_type_dao.get_all()

    async def create(self, dto: AttributeTypeDTO) -> None:
        """Create Attribute Type."""
        await self._attribute_type_dao.create(dto)

    async def update(self, _id: str, dto: AttributeTypeDTO) -> None:
        """Update Attribute Type.

        NOTE: Only 3 attrs can be updated.
        """
        await self._attribute_type_dao.update(_id, dto)

    async def delete(self, _id: str) -> None:
        """Delete Attribute Type."""
        await self._attribute_type_dao.delete(_id)

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
