"""Entity Use Case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import contextlib
from typing import ClassVar, Iterable

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from abstract_service import AbstractService
from entities import Directory, EntityType
from enums import AuthorizationRules, EntityTypeNames
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.exceptions import (
    EntityTypeAlreadyExistsError,
    EntityTypeCantModifyError,
    EntityTypeNotFoundError,
)
from ldap_protocol.ldap_schema.object_class.object_class_dao import (
    ObjectClassDAO,
)
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult
from repo.pg.tables import queryable_attr as qa


class EntityTypeUseCase(AbstractService):
    """Entity Use Case."""

    __entity_type_dao: EntityTypeDAO
    __object_class_dao: ObjectClassDAO

    def __init__(
        self,
        entity_type_dao: EntityTypeDAO,
        object_class_dao: ObjectClassDAO,
    ) -> None:
        """Initialize Entity Use Case."""
        self.__entity_type_dao = entity_type_dao
        self.__object_class_dao = object_class_dao

    async def create(self, dto: EntityTypeDTO) -> None:
        """Create Entity Type."""
        await self.__object_class_dao.is_all_object_classes_exists(
            dto.object_class_names,
        )

        await self.__entity_type_dao.create(dto)

    async def create_not_safe(self, dto: EntityTypeDTO) -> None:
        """Create Entity Type."""
        await self.__entity_type_dao.create(dto)

    async def update(self, name: str, dto: EntityTypeDTO) -> None:
        """Update Entity Type."""
        try:
            entity_type = await self.get(name)

        except EntityTypeNotFoundError:
            raise EntityTypeCantModifyError
        if entity_type.is_system:
            raise EntityTypeCantModifyError(
                f"Entity Type '{dto.name}' is system and cannot be modified.",
            )
        if name != dto.name:
            await self._validate_name(name=dto.name)

        await self.__object_class_dao.is_all_object_classes_exists(
            dto.object_class_names,
        )

        await self.__entity_type_dao.update(entity_type.name, dto)

    async def get(self, name: str) -> EntityTypeDTO:
        """Get Entity Type by name."""
        return await self.__entity_type_dao.get(name)

    async def get_one_raw_by_name(self, name: str) -> EntityType:
        return await self.__entity_type_dao.get_one_raw_by_name(name)

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
        return await self.__entity_type_dao.get_paginator(params)

    async def get_entity_type_attributes(self, name: str) -> list[str]:
        """Get entity type attributes."""
        entity_type = await self.__entity_type_dao.get_one_raw_by_name(name)

        if not entity_type.object_class_names:
            return []

        object_class_dirs = await self.__object_class_dao.get_all_by_names(
            entity_type.object_class_names,
        )

        attribute_names: set[str] = set()
        for object_class_dir in object_class_dirs:
            attribute_names.update(object_class_dir.attribute_types_may)
            attribute_names.update(object_class_dir.attribute_types_must)

        return sorted(attribute_names)

    async def get_entity_type_by_object_class_names(
        self,
        object_class_names: Iterable[str],
    ) -> EntityType | None:
        """Get Entity Type by object class names."""
        return (
            await self.__entity_type_dao.get_entity_type_by_object_class_names(
                object_class_names,
            )
        )

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete all Entity Types by names."""
        await self.__entity_type_dao.delete_all_by_names(names)

    async def attach_entity_type_to_directories(self) -> None:
        """Find all Directories without an Entity Type and attach it to them."""  # noqa: E501
        result = await self.__session.execute(
            select(Directory)
            .where(qa(Directory.entity_type_id).is_(None))
            .options(
                selectinload(qa(Directory.attributes)),
                selectinload(qa(Directory.entity_type)),
            ),
        )

        for directory in result.scalars():
            await self.attach_entity_type_to_directory(
                directory=directory,
                is_system_entity_type=False,
            )

        await self.__session.flush()

    async def attach_entity_type_to_directory(
        self,
        directory: Directory,
        is_system_entity_type: bool,
        entity_type: EntityType | None = None,
        object_class_names: set[str] | None = None,
    ) -> None:
        """Try to find the Entity Type, attach it to the Directory."""
        if entity_type:
            directory.entity_type = entity_type
            return

        if object_class_names is None:
            object_class_names = directory.object_class_names_set

        await self.__object_class_dao.is_all_object_classes_exists(
            object_class_names,
        )

        entity_type = (
            await self.__entity_type_dao.get_entity_type_by_object_class_names(
                object_class_names,
            )
        )
        if not entity_type:
            entity_type_name = EntityType.generate_entity_type_name(
                directory=directory,
            )
            with contextlib.suppress(EntityTypeAlreadyExistsError):
                await self.create(
                    EntityTypeDTO[None](
                        name=entity_type_name,
                        object_class_names=list(object_class_names),
                        is_system=is_system_entity_type,
                    ),
                )

            entity_type = await self.__entity_type_dao.get_entity_type_by_object_class_names(  # noqa: E501
                object_class_names,
            )

        directory.entity_type = entity_type

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        get.__name__: AuthorizationRules.ENTITY_TYPE_GET,
        create.__name__: AuthorizationRules.ENTITY_TYPE_CREATE,
        get_paginator.__name__: AuthorizationRules.ENTITY_TYPE_GET_PAGINATOR,
        update.__name__: AuthorizationRules.ENTITY_TYPE_UPDATE,
        delete_all_by_names.__name__: AuthorizationRules.ENTITY_TYPE_DELETE_ALL_BY_NAMES,  # noqa: E501
        get_entity_type_attributes.__name__: AuthorizationRules.ENTITY_TYPE_GET_ATTRIBUTES,  # noqa: E501
    }
