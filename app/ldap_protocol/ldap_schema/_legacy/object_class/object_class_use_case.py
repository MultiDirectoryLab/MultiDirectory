"""Object Class Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from entities_legacy import ObjectClass

from abstract_service import AbstractService
from enums import AuthorizationRules
from ldap_protocol.ldap_schema._legacy.attribute_type.attribute_type_dao import (  # noqa: E501
    AttributeTypeDAOLegacy,
)
from ldap_protocol.ldap_schema._legacy.object_class.object_class_dao import (
    ObjectClassCreateDTO,
    ObjectClassDAOLegacy,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO
from ldap_protocol.ldap_schema.exceptions import ObjectClassNotFoundError


class ObjectClassUseCaseLegacy(AbstractService):
    """ObjectClassUseCase."""

    __attribute_type_dao_legacy: AttributeTypeDAOLegacy
    __object_class_dao_legacy: ObjectClassDAOLegacy

    def __init__(
        self,
        object_class_dao_legacy: ObjectClassDAOLegacy,
        attribute_type_dao_legacy: AttributeTypeDAOLegacy,
    ) -> None:
        """Init ObjectClassUseCase."""
        self.__attribute_type_dao_legacy = attribute_type_dao_legacy
        self.__object_class_dao_legacy = object_class_dao_legacy

    async def get(self, name: str) -> ObjectClassDTO[int, AttributeTypeDTO]:
        """Get Object Class by name."""
        dto = await self.__object_class_dao_legacy.get(name)
        return dto

    async def get_all(self) -> list[ObjectClassDTO[int, AttributeTypeDTO]]:
        """Get all Object Classes."""
        return await self.__object_class_dao_legacy.get_all()

    async def create(self, dto: ObjectClassDTO[None, str]) -> None:
        """Create a new Object Class."""
        create_dto = ObjectClassCreateDTO(
            oid=dto.oid,
            name=dto.name,
            kind=dto.kind,
            is_system=dto.is_system,
            attribute_types_must=[],
            attribute_types_may=[],
        )

        if dto.superior_name:
            create_dto.superior = (
                await self.__object_class_dao_legacy.get_raw_by_name(
                    dto.superior_name,
                )
            )

        if dto.superior_name and not create_dto.superior:
            raise ObjectClassNotFoundError(
                f"Superior (parent) Object class {dto.superior_name} "
                "not found in schema.",
            )

        attribute_types_may_filtered = [
            name
            for name in dto.attribute_types_may
            if name not in dto.attribute_types_must
        ]

        if dto.attribute_types_must:
            create_dto.attribute_types_must = (
                await self.__attribute_type_dao_legacy.get_all_raw_by_names(
                    dto.attribute_types_must,
                )
            )

        if attribute_types_may_filtered:
            create_dto.attribute_types_may = (
                await self.__attribute_type_dao_legacy.get_all_raw_by_names(
                    attribute_types_may_filtered,
                )
            )

        await self.__object_class_dao_legacy.create(create_dto)

    async def get_raw_by_name(self, name: str) -> ObjectClass:
        """Get Object Class by name without related data."""
        return await self.__object_class_dao_legacy.get_raw_by_name(name)

    async def delete_table(self) -> None:
        """Delete Object Class table."""
        await self.__object_class_dao_legacy.delete_table()

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {}
