"""Attribute Type Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from sqlalchemy.exc import IntegrityError

from abstract_service import AbstractService
from enums import AuthorizationRules
from ldap_protocol.ldap_schema.attribute_type.attribute_type_dao import (
    AttributeTypeDAO,
)
from ldap_protocol.ldap_schema.attribute_type.attribute_type_dir_create_use_case import (  # noqa: E501
    CreateDirectoryLikeAsAttributeTypeUseCase,
)
from ldap_protocol.ldap_schema.attribute_type.attribute_type_system_flags_use_case import (  # noqa: E501
    AttributeTypeSystemFlagsUseCase,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
)
from ldap_protocol.ldap_schema.object_class.object_class_dao import (
    ObjectClassDAO,
)
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult


class AttributeTypeUseCase(AbstractService):
    """AttributeTypeUseCase."""

    __attribute_type_dao: AttributeTypeDAO
    __attribute_type_system_flags_use_case: AttributeTypeSystemFlagsUseCase
    __object_class_dao: ObjectClassDAO
    __create_attribute_dir_gateway: CreateDirectoryLikeAsAttributeTypeUseCase

    def __init__(
        self,
        attribute_type_dao: AttributeTypeDAO,
        attribute_type_system_flags_use_case: AttributeTypeSystemFlagsUseCase,
        object_class_dao: ObjectClassDAO,
        create_attribute_dir_use_case: CreateDirectoryLikeAsAttributeTypeUseCase,  # noqa: E501
    ) -> None:
        """Init AttributeTypeUseCase."""
        self.__attribute_type_dao = attribute_type_dao
        self.__attribute_type_system_flags_use_case = (
            attribute_type_system_flags_use_case
        )
        self.__object_class_dao = object_class_dao
        self.__create_attribute_dir_gateway = create_attribute_dir_use_case

    async def get(self, name: str) -> AttributeTypeDTO:
        """Get Attribute Type by name."""
        dto = await self.__attribute_type_dao.get(name)
        dto.object_class_names = await self.__object_class_dao.get_object_class_names_include_attribute_type(  # noqa: E501
            dto.name,
        )
        return dto

    async def get_all(self) -> list[AttributeTypeDTO]:
        """Get all Attribute Types."""
        return await self.__attribute_type_dao.get_all()

    async def create(self, dto: AttributeTypeDTO[None]) -> None:
        """Create Attribute Type."""
        try:
            await self.__create_attribute_dir_gateway.create_dir(
                data={
                    "name": dto.name,
                    "object_class": "",
                    "attributes": {
                        "objectClass": ["top", "attributeSchema"],
                        "oid": [str(dto.oid)],
                        "name": [str(dto.name)],
                        "syntax": [str(dto.syntax)],
                        "single_value": [str(dto.single_value)],
                        "no_user_modification": [
                            str(dto.no_user_modification),
                        ],
                        "system_flags": [str(dto.system_flags)],
                        "is_included_anr": [str(dto.is_included_anr)],
                    },
                    "children": [],
                },
                is_system=dto.is_system,
            )

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
        dto = self.__attribute_type_system_flags_use_case.set_attr_replication_flag(  # noqa: E501
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
        get_paginator.__name__: AuthorizationRules.ATTRIBUTE_TYPE_GET_PAGINATOR,  # noqa: E501
        update.__name__: AuthorizationRules.ATTRIBUTE_TYPE_UPDATE,
        delete_all_by_names.__name__: AuthorizationRules.ATTRIBUTE_TYPE_DELETE_ALL_BY_NAMES,  # noqa: E501
    }
