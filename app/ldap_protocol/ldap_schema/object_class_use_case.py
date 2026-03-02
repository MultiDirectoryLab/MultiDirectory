"""Object Class Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from entities_appendix import ObjectClass

from abstract_service import AbstractService
from enums import AuthorizationRules
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult


class ObjectClassUseCase(AbstractService):
    """ObjectClassUseCase."""

    def __init__(
        self,
        attribute_type_dao: AttributeTypeDAO,
        object_class_dao: ObjectClassDAO,
        entity_type_dao: EntityTypeDAO,
    ) -> None:
        """Init ObjectClassUseCase."""
        self._attribute_type_dao = attribute_type_dao
        self._object_class_dao = object_class_dao
        self._entity_type_dao = entity_type_dao

    async def get_all(self) -> list[ObjectClassDTO[int, AttributeTypeDTO]]:
        """Get all Object Classes."""
        return await self._object_class_dao.get_all()

    async def delete(self, name: str) -> None:
        """Delete Object Class."""
        await self._object_class_dao.delete(name)

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated Object Classes."""
        return await self._object_class_dao.get_paginator(params)

    async def create(self, dto: ObjectClassDTO[None, str]) -> None:
        """Create a new Object Class."""
        attribute_types_may_filtered = [
            name
            for name in dto.attribute_types_may
            if name not in dto.attribute_types_must
        ]

        if dto.attribute_types_must:
            dto.attribute_types_must = (
                await self._attribute_type_dao.get_all_names_by_names(
                    dto.attribute_types_must,
                )
            )
        else:
            dto.attribute_types_must = []

        if attribute_types_may_filtered:
            dto.attribute_types_may = (
                await self._attribute_type_dao.get_all_names_by_names(
                    attribute_types_may_filtered,
                )
            )
        else:
            dto.attribute_types_may = []

        await self._object_class_dao.create(dto)

    async def create_ldap(self, dto: ObjectClassDTO[None, str]) -> None:
        """Create a new Object Class."""
        await self._object_class_dao.create_ldap(dto)

    async def get_raw_by_name(self, name: str) -> ObjectClass:
        """Get Object Class by name without related data."""
        return await self._object_class_dao.get_raw_by_name(name)

    async def get(self, name: str) -> ObjectClassDTO:
        """Get Object Class by name."""
        dto = await self._object_class_dao.get(name)
        dto.entity_type_names = (
            await self._entity_type_dao.get_entity_type_names_include_oc_name(
                dto.name,
            )
        )
        return dto

    async def get_all_by_names(
        self,
        names: list[str] | set[str],
    ) -> list[ObjectClassDTO]:
        """Get list of Object Classes by names."""
        return await self._object_class_dao.get_all_by_names(names)

    async def update(self, name: str, dto: ObjectClassDTO[None, str]) -> None:
        """Modify Object Class."""
        await self._object_class_dao.update(name, dto)

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Object Classes by Names."""
        await self._object_class_dao.delete_all_by_names(names)

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        get.__name__: AuthorizationRules.OBJECT_CLASS_GET,
        create.__name__: AuthorizationRules.OBJECT_CLASS_CREATE,
        get_paginator.__name__: AuthorizationRules.OBJECT_CLASS_GET_PAGINATOR,
        update.__name__: AuthorizationRules.OBJECT_CLASS_UPDATE,
        delete_all_by_names.__name__: AuthorizationRules.OBJECT_CLASS_DELETE_ALL_BY_NAMES,  # noqa: E501
    }
