"""File for LDAPEntityTypeFastAPIAdapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix.conversion import get_converter
from fastapi import status

from api.base_adapter import BaseAdapter
from api.ldap_schema.adapters.base_ldap_schema_adapter import (
    BaseLDAPSchemaAdapter,
)
from api.ldap_schema.schema import (
    EntityTypePaginationSchema,
    EntityTypeSchema,
    EntityTypeUpdateSchema,
)
from ldap_protocol.ldap_schema.constants import DEFAULT_ENTITY_TYPE_IS_SYSTEM
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.ldap_schema.exceptions import (
    EntityTypeCantModifyError,
    EntityTypeNotFoundError,
    ObjectClassNotFoundError,
)
from ldap_protocol.permissions_checker import ApiPermissionError


def _convert_update_chema_to_dto(
    data: EntityTypeUpdateSchema,
) -> EntityTypeDTO:
    """Convert EntityTypeUpdateSchema to EntityTypeDTO."""
    return EntityTypeDTO(
        name=data.name,
        is_system=DEFAULT_ENTITY_TYPE_IS_SYSTEM,
        object_class_names=data.object_class_names,
    )


_convert_request_to_dto = get_converter(
    EntityTypeSchema[None],
    EntityTypeDTO[None],
)

_convert_dto_to_schema = get_converter(
    EntityTypeDTO[int],
    EntityTypeSchema[int],
)


class LDAPEntityTypeFastAPIAdapter(
    BaseAdapter[EntityTypeUseCase],
    BaseLDAPSchemaAdapter[
        EntityTypeUseCase,
        EntityTypeSchema,
        EntityTypeUpdateSchema,
        EntityTypePaginationSchema,
        EntityTypeDTO,
    ],
):
    """Adapter for LDAP Entity Type router."""

    _pagination_schema = EntityTypePaginationSchema

    _converter_to_dto = staticmethod(_convert_request_to_dto)
    _converter_to_schema = staticmethod(_convert_dto_to_schema)
    _converter_update_sch_to_dto = staticmethod(_convert_update_chema_to_dto)

    _exceptions_map: dict[type[Exception], int] = {
        EntityTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        EntityTypeCantModifyError: status.HTTP_403_FORBIDDEN,
        ObjectClassNotFoundError: status.HTTP_404_NOT_FOUND,
        ApiPermissionError: status.HTTP_403_FORBIDDEN,
    }

    async def get_entity_type_attributes(self, name: str) -> list[str]:
        """Get all attribute names for an Entity Type.

        :param str name: Entity Type name.
        :return list[str]: List of attribute names.
        """
        return await self._service.get_entity_type_attributes(name)
