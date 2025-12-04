"""Entity Use Case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from abstract_service import AbstractService
from constants import ENTITY_TYPE_DATAS
from enums import AuthorizationRules, EntityTypeNames
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.exceptions import (
    EntityTypeCantModifyError,
    EntityTypeNotFoundError,
)
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult


class EntityTypeUseCase(AbstractService):
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

    async def create(self, dto: EntityTypeDTO) -> None:
        """Create Entity Type."""
        await self._object_class_dao.is_all_object_classes_exists(
            dto.object_class_names,
        )
        await self._entity_type_dao.create(dto)

    async def update(self, _id: str, dto: EntityTypeDTO) -> None:
        """Update Entity Type."""
        try:
            entity_type = await self.get(_id)

        except EntityTypeNotFoundError:
            raise EntityTypeCantModifyError
        if entity_type.is_system:
            raise EntityTypeCantModifyError(
                f"Entity Type '{dto.name}' is system and cannot be modified.",
            )
        if _id != dto.name:
            await self._validate_name(name=_id)
        await self._entity_type_dao.update(entity_type.name, dto)

    async def get(self, _id: str) -> EntityTypeDTO:
        """Get Entity Type by name."""
        return await self._entity_type_dao.get(_id)

    async def _validate_name(
        self,
        name: str,
    ) -> None:
        if name in EntityTypeNames:
            raise EntityTypeCantModifyError(
                f"Can't change entity type name {name}",
            )

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Get paginated Entity Types."""
        return await self._entity_type_dao.get_paginator(params)

    async def get_entity_type_attributes(self, name: str) -> list[str]:
        """Get entity type attributes."""
        return await self._entity_type_dao.get_entity_type_attributes(name)

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete all Entity Types by names."""
        await self._entity_type_dao.delete_all_by_names(names)

    async def create_for_first_setup(self) -> None:
        """Create Entity Types for first setup.

        :return: None.
        """
        for entity_type_data in ENTITY_TYPE_DATAS:
            await self.create(
                EntityTypeDTO(
                    name=entity_type_data["name"],
                    object_class_names=list(
                        entity_type_data["object_class_names"],
                    ),
                    is_system=True,
                ),
            )

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        get.__name__: AuthorizationRules.ENTITY_TYPE_GET,
        create.__name__: AuthorizationRules.ENTITY_TYPE_CREATE,
        get_paginator.__name__: AuthorizationRules.ENTITY_TYPE_GET_PAGINATOR,
        update.__name__: AuthorizationRules.ENTITY_TYPE_UPDATE,
        delete_all_by_names.__name__: AuthorizationRules.ENTITY_TYPE_DELETE_ALL_BY_NAMES,  # noqa: E501
        get_entity_type_attributes.__name__: AuthorizationRules.ENTITY_TYPE_GET_ATTRIBUTES,  # noqa: E501
    }
