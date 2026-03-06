"""Object Class Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from entities_legacy import ObjectClass

from abstract_service import AbstractService
from enums import AuthorizationRules
from ldap_protocol.ldap_schema._legacy.object_class.object_class_dao import (
    ObjectClassDAOLegacy,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO


class ObjectClassUseCaseLegacy(AbstractService):
    """ObjectClassUseCase."""

    __object_class_dao_legacy: ObjectClassDAOLegacy

    def __init__(self, object_class_dao_legacy: ObjectClassDAOLegacy) -> None:
        """Init ObjectClassUseCase."""
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
        await self.__object_class_dao_legacy.create(dto)

    async def get_raw_by_name(self, name: str) -> ObjectClass:
        """Get Object Class by name without related data."""
        return await self.__object_class_dao_legacy.get_raw_by_name(name)

    async def delete_table(self) -> None:
        """Delete Object Class table."""
        await self.__object_class_dao_legacy.delete_table()

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {}
