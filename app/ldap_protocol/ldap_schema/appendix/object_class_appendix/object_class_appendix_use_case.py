"""Object Class Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from entities_appendix import ObjectClass

from abstract_service import AbstractService
from enums import AuthorizationRules
from ldap_protocol.ldap_schema.appendix.entity_type_appendix.entity_type_appendix_dao import (
    EntityTypeDAODeprecated,
)
from ldap_protocol.ldap_schema.appendix.object_class_appendix.object_class_appendix_dao import (
    ObjectClassDAODeprecated,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult


class ObjectClassUseCaseDeprecated(AbstractService):
    """ObjectClassUseCase."""

    def __init__(
        self,
        object_class_dao: ObjectClassDAODeprecated,
        entity_type_dao: EntityTypeDAODeprecated,
    ) -> None:
        """Init ObjectClassUseCase."""
        self._object_class_dao = object_class_dao
        self._entity_type_dao = entity_type_dao

    async def create(self, dto: ObjectClassDTO[None, str]) -> None:  # noqa: ARG002
        raise

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

    async def create_deprecated(self, dto: ObjectClassDTO[None, str]) -> None:
        """Create a new Object Class."""
        await self._object_class_dao.create_deprecated(dto)

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

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {}
