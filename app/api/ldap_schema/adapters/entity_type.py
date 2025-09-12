"""File for LDAPEntityTypeFastAPIAdapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import (
    allow_unlinked_optional,
    get_converter,
    link_function,
)
from fastapi import status

from api.base_adapter import BaseAdapter
from api.ldap_schema.adapters.base_ldap_schema_adapter import BaseLDAPSchema
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


def make_entity_type_request_dto(
    request: EntityTypeSchema,
) -> EntityTypeDTO:
    """Convert EntityTypeSchema to EntityTypeDTO."""
    return EntityTypeDTO(
        name=request.name,
        is_system=DEFAULT_ENTITY_TYPE_IS_SYSTEM,
        object_class_names=request.object_class_names,
    )


def make_entity_type_shema_by_update(
    data: EntityTypeUpdateSchema,
) -> EntityTypeSchema:
    """Convert EntityTypeUpdateSchema to EntityTypeSchema."""
    return EntityTypeSchema(
        is_system=DEFAULT_ENTITY_TYPE_IS_SYSTEM,
        name=data.name,
        object_class_names=data.object_class_names,
    )


def make_entity_type_schema(dto: EntityTypeDTO) -> EntityTypeSchema:
    """Convert EntityTypeDTO to EntityTypeSchema."""
    return EntityTypeSchema(
        id=dto.get_id(),
        name=dto.name,
        object_class_names=dto.object_class_names,
        is_system=dto.is_system,
    )


_convert_request_to_dto = get_converter(
    EntityTypeSchema,
    EntityTypeDTO,
    recipe=[
        link_function(make_entity_type_request_dto, P[EntityTypeDTO]),
        allow_unlinked_optional(P[EntityTypeDTO].id),
    ],
)

_convert_dto_to_schema = get_converter(
    EntityTypeDTO,
    EntityTypeSchema,
    recipe=[
        link_function(
            lambda dto: dto.get_id(),
            P[EntityTypeSchema].id,
        ),
    ],
)
_convert_to_base_schema = get_converter(
    EntityTypeUpdateSchema,
    EntityTypeSchema,
    recipe=[
        link_function(
            lambda data: EntityTypeSchema(
                is_system=DEFAULT_ENTITY_TYPE_IS_SYSTEM,
                name=data.name,
                object_class_names=data.object_class_names,
            ),
            P[EntityTypeSchema],
        ),
    ],
)


class LDAPEntityTypeFastAPIAdapter(
    BaseAdapter[EntityTypeUseCase],
    BaseLDAPSchema,
):
    """Adapter for LDAP Entity Type router."""

    _schema = EntityTypeSchema
    _pagination_schema = EntityTypePaginationSchema
    _request_schema = EntityTypeSchema
    _update_schema = EntityTypeUpdateSchema
    _dto = EntityTypeDTO
    converter_to_dto = _convert_request_to_dto
    converter_to_schema = _convert_dto_to_schema
    converter_to_base_schema = make_entity_type_shema_by_update

    _exceptions_map: dict[type[Exception], int] = {
        EntityTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        EntityTypeCantModifyError: status.HTTP_403_FORBIDDEN,
        ObjectClassNotFoundError: status.HTTP_404_NOT_FOUND,
    }

    async def get_entity_type_attributes(
        self,
        name: str,
    ) -> list[str]:
        """Get all attribute names for an Entity Type.

        \f
        :param str name: Entity Type name.
        :return list[str]: List of attribute names.
        """
        return await self._service.get_entity_type_attributes(name)
