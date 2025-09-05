"""Entity Use Case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abstract_dao import AbstractService
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.exceptions import EntityTypeCantModifyError
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult


class EntityUseCase(AbstractService):
    """Entity Use Case."""

    def __init__(
        self,
        entity_type_dao: EntityTypeDAO,
        object_class_dao: ObjectClassDAO,
    ) -> None:
        """Initialize Entity Use Case.

        :param EntityTypeDAO entity_type_dao: Entity Type DAO.
        :param ObjectClassDAO object_class_dao: Object Class DAO.
        """
        self._entity_type_dao = entity_type_dao
        self._object_class_dao = object_class_dao

    async def create(self, entity_type_dto: EntityTypeDTO) -> None:
        """Create Entity Type."""
        await self._object_class_dao.is_all_object_classes_exists(
            entity_type_dto.object_class_names,
        )
        await self._entity_type_dao.create(entity_type_dto)

    async def update(
        self,
        entity_type_dto: EntityTypeDTO,
        request_name: str,
    ) -> None:
        """Update Entity Type."""
        if entity_type_dto.is_system:
            raise EntityTypeCantModifyError(
                f"Entity Type '{entity_type_dto.name}' is system and "
                f"cannot be modified.",
            )
        if request_name != entity_type_dto.name:
            await self._entity_type_dao.validate_name(
                name=request_name,
            )
        await self._entity_type_dao.update(
            entity_type_dto.get_id(),
            entity_type_dto,
        )

    async def get_by_name(self, entity_type_name: str) -> EntityTypeDTO:
        """Get Entity Type by name."""
        return await self._entity_type_dao.get_one_by_name(entity_type_name)

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Get paginated Entity Types."""
        return await self._entity_type_dao.get_paginator(params)

    async def get_entity_type_attributes(
        self,
        entity_type_name: str,
    ) -> list[str]:
        """Get entity type attributes."""
        return await self._entity_type_dao.get_entity_type_attributes(
            entity_type_name,
        )

    async def delete_all_by_names(
        self,
        entity_type_names: list[str],
    ) -> None:
        """Delete all Entity Types by names."""
        await self._entity_type_dao.delete_all_by_names(entity_type_names)
