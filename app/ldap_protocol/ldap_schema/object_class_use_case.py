"""Object Class Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abstract_dao import AbstractService
from enums import ApiPermissionsType
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult


class ObjectClassUseCase(AbstractService):
    """ObjectClassUseCase."""

    _usecase_api_permissions: dict[str, ApiPermissionsType] = {
        "get": ApiPermissionsType.OBJECT_CLASS_GET,
        "create": ApiPermissionsType.OBJECT_CLASS_CREATE,
        "get_paginator": ApiPermissionsType.OBJECT_CLASS_GET_PAGINATOR,
        "update": ApiPermissionsType.OBJECT_CLASS_UPDATE,
        "delete_all_by_names": ApiPermissionsType.OBJECT_CLASS_DELETE_ALL_BY_NAMES,  # noqa: E501
    }

    def __init__(
        self,
        object_class_dao: ObjectClassDAO,
        entity_type_dao: EntityTypeDAO,
    ) -> None:
        """Init ObjectClassUseCase."""
        self._object_class_dao = object_class_dao
        self._entity_type_dao = entity_type_dao

    async def get_all(self) -> list[ObjectClassDTO[int, AttributeTypeDTO]]:
        """Get all Object Classes."""
        return await self._object_class_dao.get_all()

    async def delete(self, _id: str) -> None:
        """Delete Object Class."""
        await self._object_class_dao.delete(_id)

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated Object Classes."""
        return await self._object_class_dao.get_paginator(params)

    async def create(self, dto: ObjectClassDTO[None, str]) -> None:
        """Create a new Object Class."""
        await self._object_class_dao.create(dto)

    async def get(self, _id: str) -> ObjectClassDTO:
        """Get Object Class by id."""
        dto = await self._object_class_dao.get(_id)
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

    async def update(self, _id: str, dto: ObjectClassDTO[None, str]) -> None:
        """Modify Object Class."""
        await self._object_class_dao.update(_id, dto)

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Object Classes by Names."""
        await self._object_class_dao.delete_all_by_names(names)
