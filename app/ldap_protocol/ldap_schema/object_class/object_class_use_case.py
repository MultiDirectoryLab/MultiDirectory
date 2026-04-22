"""Object Class Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import TYPE_CHECKING, ClassVar

from sqlalchemy.exc import IntegrityError

from abstract_service import AbstractService
from constants import OBJECT_CLASS_OBJECT_CLASS_NAMES
from enums import AuthorizationRules, EntityTypeNames
from ldap_protocol.ldap_schema.attribute_type.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.directory_create_use_case import DirectoryCreateUseCase
from ldap_protocol.ldap_schema.dto import AttributeDTO, DirCreateDTO, ObjectClassDTO
from ldap_protocol.ldap_schema.entity_type.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.exceptions import ObjectClassAlreadyExistsError, ObjectClassNotFoundError
from ldap_protocol.ldap_schema.object_class.constants import ObjectClassAttributeNames as Names
from ldap_protocol.ldap_schema.object_class.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult

if TYPE_CHECKING:
    from entities import Directory


class ObjectClassUseCase(AbstractService):
    """ObjectClassUseCase."""

    __attribute_type_dao: AttributeTypeDAO
    __object_class_dao: ObjectClassDAO
    __entity_type_dao: EntityTypeDAO
    __directory_create_use_case: DirectoryCreateUseCase
    __parent_dir: "Directory | None"

    def __init__(
        self,
        attribute_type_dao: AttributeTypeDAO,
        object_class_dao: ObjectClassDAO,
        entity_type_dao: EntityTypeDAO,
        directory_create_use_case: DirectoryCreateUseCase,
    ) -> None:
        """Init ObjectClassUseCase."""
        self.__attribute_type_dao = attribute_type_dao
        self.__object_class_dao = object_class_dao
        self.__entity_type_dao = entity_type_dao
        self.__directory_create_use_case = directory_create_use_case
        self.__parent_dir = None

    async def get_all(self) -> list[ObjectClassDTO[int, str]]:
        """Get all Object Classes."""
        return await self.__object_class_dao.get_all()

    async def delete(self, name: str) -> None:
        """Delete Object Class."""
        await self.__object_class_dao.delete(name)

    async def get_paginator(self, params: PaginationParams) -> PaginationResult:
        """Retrieve paginated Object Classes."""
        return await self.__object_class_dao.get_paginator(params)

    async def create(self, dto: ObjectClassDTO[None, str]) -> None:
        """Create a new Object Class."""
        if not self.__parent_dir:
            self.__parent_dir = await self.__directory_create_use_case.get_configuration_dir()

        attribute_types_may_filtered = [
            name for name in dto.attribute_types_may if name not in dto.attribute_types_must
        ]

        if dto.attribute_types_must:
            dto.attribute_types_must = await self.__attribute_type_dao.get_all_names_by_names(dto.attribute_types_must)

        if attribute_types_may_filtered:
            dto.attribute_types_may = await self.__attribute_type_dao.get_all_names_by_names(
                attribute_types_may_filtered
            )

        superior = None
        if dto.superior_name:
            superior = await self.__object_class_dao.get(dto.superior_name)

            if not superior:
                raise ObjectClassNotFoundError(
                    f"Superior (parent) Object class {dto.superior_name} not found in schema."
                )

        attributes = [
            AttributeDTO(name=Names.OBJECT_CLASS, values=OBJECT_CLASS_OBJECT_CLASS_NAMES),
            AttributeDTO(name=Names.OID, values=[str(dto.oid)]),
            AttributeDTO(name=Names.KIND, values=[dto.kind.value]),
            AttributeDTO(name=Names.ATTRIBUTE_TYPES_MUST, values=dto.attribute_types_must),
            AttributeDTO(name=Names.ATTRIBUTE_TYPES_MAY, values=dto.attribute_types_may),
        ]

        if dto.superior_name:
            attributes.append(AttributeDTO(name=Names.SUPERIOR_NAME, values=[dto.superior_name]))

        _dir_create_dto = DirCreateDTO(
            name=dto.name,
            entity_type_name=EntityTypeNames.OBJECT_CLASS,
            attributes=tuple(attributes),
            is_system=dto.is_system,
        )
        try:
            await self.__directory_create_use_case.create_dir(dto=_dir_create_dto, parent_dir=self.__parent_dir)
        except IntegrityError:
            raise ObjectClassAlreadyExistsError(
                f"Object Class with oid '{dto.oid}' and name" + f" '{dto.name}' already exists."
            )

    async def get(self, name: str) -> ObjectClassDTO:
        """Get Object Class by name."""
        dto = await self.__object_class_dao.get(name)
        dto.entity_type_names = await self.__entity_type_dao.get_entity_type_names_include_oc_name(dto.name)
        return dto

    async def update(self, name: str, dto: ObjectClassDTO[None, str]) -> None:
        """Modify Object Class."""
        dto.attribute_types_must = await self.__attribute_type_dao.get_all_names_by_names(dto.attribute_types_must)
        dto.attribute_types_may = [
            name
            for name in await self.__attribute_type_dao.get_all_names_by_names(dto.attribute_types_may)
            if name not in dto.attribute_types_must
        ]
        await self.__object_class_dao.update(name, dto)

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Object Classes by Names."""
        await self.__object_class_dao.delete_all_by_names(names)

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        get.__name__: AuthorizationRules.OBJECT_CLASS_GET,
        create.__name__: AuthorizationRules.OBJECT_CLASS_CREATE,
        update.__name__: AuthorizationRules.OBJECT_CLASS_UPDATE,
        delete_all_by_names.__name__: AuthorizationRules.OBJECT_CLASS_DELETE_ALL_BY_NAMES,
    }
