"""Attribute Type Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from sqlalchemy.exc import IntegrityError

from abstract_service import AbstractService
from enums import AuthorizationRules, EntityTypeNames
from ldap_protocol.ldap_schema.attribute_type.attribute_type_dao import (
    AttributeTypeDAO,
)
from ldap_protocol.ldap_schema.attribute_type.attribute_type_system_flags_use_case import (  # noqa: E501
    AttributeTypeSystemFlagsUseCase,
)
from ldap_protocol.ldap_schema.attribute_type.constants import (
    AttributeTypeAttributeNames as Names,
)
from ldap_protocol.ldap_schema.dto import (
    AttributeDTO,
    AttributeTypeDTO,
    CreateDirDTO,
)
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
)
from ldap_protocol.ldap_schema.object_class.object_class_dao import (
    ObjectClassDAO,
)
from ldap_protocol.ldap_schema.schema_create_use_case import (
    DirectoryCreateUseCase,
)
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult


class AttributeTypeUseCase(AbstractService):
    """AttributeTypeUseCase."""

    __attribute_type_dao: AttributeTypeDAO
    __attribute_type_system_flags_use_case: AttributeTypeSystemFlagsUseCase
    __object_class_dao: ObjectClassDAO
    __directory_create_use_case: DirectoryCreateUseCase

    def __init__(
        self,
        attribute_type_dao: AttributeTypeDAO,
        attribute_type_system_flags_use_case: AttributeTypeSystemFlagsUseCase,
        object_class_dao: ObjectClassDAO,
        directory_create_use_case: DirectoryCreateUseCase,
    ) -> None:
        """Init AttributeTypeUseCase."""
        self.__attribute_type_dao = attribute_type_dao
        self.__attribute_type_system_flags_use_case = attribute_type_system_flags_use_case  # noqa: E501 # fmt: skip
        self.__object_class_dao = object_class_dao
        self.__directory_create_use_case = directory_create_use_case

    async def get(self, name: str) -> AttributeTypeDTO[int]:
        """Get Attribute Type by name."""
        dto = await self.__attribute_type_dao.get(name)
        dto.object_class_names = await self.__object_class_dao.get_object_class_names_include_attribute_type(  # noqa: E501
            dto.name,
        )
        return dto

    async def get_all(self) -> list[AttributeTypeDTO[int]]:
        """Get all Attribute Types."""
        return await self.__attribute_type_dao.get_all()

    async def create(self, dto: AttributeTypeDTO) -> None:
        """Create Attribute Type."""
        if not dto.ldap_display_name:
            dto.ldap_display_name = f"{dto.name[0].lower()}{dto.name.replace('-', '')[1:]}"  # noqa: E501  # fmt: skip

        _dto = CreateDirDTO(
            name=dto.name,
            entity_type_name=EntityTypeNames.ATTRIBUTE_TYPE,
            attributes=(
                AttributeDTO(name=Names.OID, values=[str(dto.oid)]),
                AttributeDTO(name=Names.NAME, values=[str(dto.name)]),
                AttributeDTO(
                    name=Names.LDAP_DISPLAY_NAME,
                    values=[str(dto.ldap_display_name)],
                ),
                AttributeDTO(name=Names.SYNTAX, values=[str(dto.syntax)]),
                AttributeDTO(
                    name=Names.SINGLE_VALUE,
                    values=[str(dto.single_value)],
                ),
                AttributeDTO(
                    name=Names.NO_USER_MODIFICATION,
                    values=[str(dto.no_user_modification)],
                ),
                AttributeDTO(
                    name=Names.SYSTEM_FLAGS,
                    values=[str(dto.system_flags)],
                ),
                AttributeDTO(
                    name=Names.IS_INCLUDED_ANR,
                    values=[str(dto.is_included_anr)],
                ),
            ),
            is_system=dto.is_system,
        )
        try:
            await self.__directory_create_use_case.create_dir(dto=_dto)
        except IntegrityError:
            raise AttributeTypeAlreadyExistsError(
                f"Attribute Type with oid '{dto.oid}' and name"
                + f" '{dto.name}' already exists.",
            )

    async def update(self, name: str, dto: AttributeTypeDTO) -> None:
        """Update Attribute Type."""
        await self.__attribute_type_dao.update(name, dto)

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated Attribute Types."""
        return await self.__attribute_type_dao.get_paginator(params)

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Attribute Types by names."""
        return await self.__attribute_type_dao.delete_all_by_names(names)

    async def is_attr_replicated(self, name: str) -> bool:
        """Check if attribute is replicated based on systemFlags."""
        dto = await self.__attribute_type_dao.get(name)
        return self.__attribute_type_system_flags_use_case.is_attr_replicated(dto)  # noqa: E501  # fmt: skip

    async def set_attr_replication_flag(
        self,
        name: str,
        need_to_replicate: bool,
    ) -> None:
        """Set replication flag in systemFlags."""
        dto = await self.get(name)
        dto = self.__attribute_type_system_flags_use_case.set_attr_replication(
            dto,
            need_to_replicate,
        )
        await self.__attribute_type_dao.update_sys_flags(
            dto.name,
            dto,
        )

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        get.__name__: AuthorizationRules.ATTRIBUTE_TYPE_GET,
        create.__name__: AuthorizationRules.ATTRIBUTE_TYPE_CREATE,
        update.__name__: AuthorizationRules.ATTRIBUTE_TYPE_UPDATE,
        delete_all_by_names.__name__: AuthorizationRules.ATTRIBUTE_TYPE_DELETE_ALL_BY_NAMES,  # noqa: E501
    }
