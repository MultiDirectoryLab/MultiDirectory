"""Object Class Use Case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from entities_appendix import ObjectClass

from abstract_service import AbstractService
from enums import AuthorizationRules
from ldap_protocol.ldap_schema.appendix.object_class_appendix.object_class_appendix_dao import (  # noqa: E501
    ObjectClassDAODeprecated,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO


class ObjectClassUseCaseDeprecated(AbstractService):
    """ObjectClassUseCase."""

    def __init__(
        self,
        object_class_dao: ObjectClassDAODeprecated,
    ) -> None:
        """Init ObjectClassUseCase."""
        self._object_class_dao = object_class_dao

    async def get_all(self) -> list[ObjectClassDTO[int, AttributeTypeDTO]]:
        """Get all Object Classes."""
        return await self._object_class_dao.get_all()

    async def create(self, dto: ObjectClassDTO[None, str]) -> None:
        """Create a new Object Class."""
        await self._object_class_dao.create(dto)

    async def get_raw_by_name(self, name: str) -> ObjectClass:
        """Get Object Class by name without related data."""
        return await self._object_class_dao.get_raw_by_name(name)

    async def delete_table_deprecated(self) -> None:
        """Delete Object Class table."""
        await self._object_class_dao.delete_table_deprecated()

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {}
