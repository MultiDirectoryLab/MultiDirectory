"""File for LDAPEntityTypeFastAPIAdapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Callable

from adaptix import P
from adaptix.conversion import (
    allow_unlinked_optional,
    get_converter,
    link_function,
)
from fastapi import status

from api.ldap_schema import LimitedListType
from api.ldap_schema.adapters.base_ldap_schema_adapter import (
    BaseLDAPSchemaFastAPIAdapter,
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
from ldap_protocol.utils.pagination import PaginationParams


def make_entity_type_request_dto(
    request: EntityTypeSchema,
) -> EntityTypeDTO:
    """Convert EntityTypeSchema to EntityTypeDTO."""
    return EntityTypeDTO(
        name=request.name,
        is_system=DEFAULT_ENTITY_TYPE_IS_SYSTEM,
        object_class_names=request.object_class_names,
    )


def make_entity_type_schema(dto: EntityTypeDTO) -> EntityTypeSchema:
    """Convert EntityTypeDTO to EntityTypeSchema."""
    return EntityTypeSchema(
        id=dto.id or 0,  # Handle None id
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
            lambda dto: dto.id or 0,
            P[EntityTypeSchema].id,
        ),
    ],
)


class LDAPEntityTypeFastAPIAdapter(
    BaseLDAPSchemaFastAPIAdapter[
        EntityTypeUseCase,
        EntityTypeSchema,
        EntityTypePaginationSchema,
        EntityTypeSchema,  # TO_DO TRequestSchema
        EntityTypeUpdateSchema,
        EntityTypeDTO,
    ],
):
    """Adapter for LDAProuter."""

    _exceptions_map: dict[type[Exception], int] = {
        EntityTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        EntityTypeCantModifyError: status.HTTP_403_FORBIDDEN,
        ObjectClassNotFoundError: status.HTTP_404_NOT_FOUND,
    }

    def _get_converter(self) -> tuple[Callable, Callable]:
        """Get converter functions for EntityType schema <-> DTO."""
        return (
            _convert_dto_to_schema,
            _convert_request_to_dto,
        )

    async def update(
        self,
        name: str,
        request_data: EntityTypeUpdateSchema,
    ) -> None:
        """Modify an Entity Type.

        \f
        :param str name: Name of the Entity Type for modifying.
        :param EntityTypeUpdateDTO request_data: Changed data.
        :return None.
        """
        try:
            entity_type = await self._service.get_by_name(name=name)
        except EntityTypeNotFoundError:
            raise EntityTypeCantModifyError

        updated_entity_type = EntityTypeDTO(
            id=entity_type.id,
            name=request_data.name,
            object_class_names=request_data.object_class_names,
            is_system=entity_type.is_system,
        )

        await self._service.update(updated_entity_type, request_data.name)

    async def get_list_paginated(
        self,
        params: PaginationParams,
    ) -> EntityTypePaginationSchema:
        """Retrieve a chunk of Entity Types with pagination.

        \f
        :param PaginationParams params: Pagination parameters.
        :return EntityTypePaginationSchema: Paginator Schema.
        """
        pagination_result = await self._service.get_paginator(
            params=params,
        )

        items = [
            _convert_dto_to_schema(item) for item in pagination_result.items
        ]
        return EntityTypePaginationSchema(
            metadata=pagination_result.metadata,
            items=items,
        )

    async def get(
        self,
        name: str,
    ) -> EntityTypeSchema:
        """Retrieve a one Entity Type.

        \f
        :param str name: name of the Entity Type.
        :return EntityTypeSchema: Entity Type Schema.
        """
        entity_type = await self._service.get_by_name(name=name)
        return _convert_dto_to_schema(entity_type)

    async def create(self, request_data: EntityTypeSchema) -> None:
        """Create a new Entity Type.

        \f
        :param EntityTypeSchema request_data: Data for creating
        a new Entity Type.
        :return None.
        """
        dto = _convert_request_to_dto(request_data)
        await self._service.create(dto)

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

    async def delete_bulk(self, names: LimitedListType) -> None:
        """Delete multiple Entity Types.

        \f
        :param LimitedListType names: Names of the
        Entity Types to delete.
        :return None.
        """
        await self._service.delete_all_by_names(names=names)
