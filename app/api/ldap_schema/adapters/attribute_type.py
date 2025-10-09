"""Attribute Type management routers.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from __future__ import annotations

from adaptix import P
from adaptix.conversion import (
    allow_unlinked_optional,
    get_converter,
    link_function,
)
from fastapi import status

from api.base_adapter import BaseAdapter
from api.ldap_schema import LimitedListType
from api.ldap_schema.schema import (
    AttributeTypeExtendedSchema,
    AttributeTypePaginationSchema,
    AttributeTypeSchema,
    AttributeTypeUpdateSchema,
)
from ldap_protocol.ldap_schema.constants import (
    DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM,
    DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
    DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
)
from ldap_protocol.ldap_schema.dto import (
    AttributeTypeDTO,
    AttributeTypeExtendedDTO,
)
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
    AttributeTypeCantModifyError,
    AttributeTypeNotFoundError,
)
from ldap_protocol.ldap_schema.use_cases import AttributeTypeUseCase
from ldap_protocol.utils.pagination import PaginationParams


def _convert_update_uschema_to_dto(
    request: AttributeTypeUpdateSchema,
) -> AttributeTypeDTO[None]:
    """Convert AttributeTypeUpdateSchema to AttributeTypeDTO for update."""
    return AttributeTypeDTO(
        oid="",
        name="",
        syntax=request.syntax,
        single_value=request.single_value,
        no_user_modification=request.no_user_modification,
        is_system=False,
    )


_convert_schema_to_dto = get_converter(
    AttributeTypeSchema[None],
    AttributeTypeDTO[None],
    recipe=[
        allow_unlinked_optional(P[AttributeTypeDTO].id),
        link_function(
            lambda _: DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
            P[AttributeTypeDTO].syntax,
        ),
        link_function(
            lambda _: DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
            P[AttributeTypeDTO].no_user_modification,
        ),
        link_function(
            lambda _: DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM,
            P[AttributeTypeDTO].is_system,
        ),
    ],
)

_convert_dto_to_schema = get_converter(
    AttributeTypeDTO[int],
    AttributeTypeSchema[int],
)
_convert_to_extended_schema = get_converter(
    AttributeTypeExtendedDTO,
    AttributeTypeExtendedSchema,
)


class AttributeTypeFastAPIAdapter(BaseAdapter[AttributeTypeUseCase]):
    """Attribute Type management routers."""

    _pagination_schema = AttributeTypePaginationSchema

    _converter_to_dto = staticmethod(_convert_schema_to_dto)
    _converter_to_schema = staticmethod(_convert_dto_to_schema)
    _converter_to_extended_schema = staticmethod(_convert_to_extended_schema)
    _converter_update_sch_to_dto = staticmethod(_convert_update_uschema_to_dto)

    _exceptions_map: dict[type[Exception], int] = {
        AttributeTypeAlreadyExistsError: status.HTTP_409_CONFLICT,
        AttributeTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        AttributeTypeCantModifyError: status.HTTP_403_FORBIDDEN,
    }

    async def create(self, data: AttributeTypeSchema) -> None:
        """Create a new entity.

        :param request_data: Data for creating entity.
        """
        dto = self._converter_to_dto(data)
        await self._service.create(dto)

    async def get(
        self,
        name: str,
    ) -> AttributeTypeExtendedSchema:
        """Get a single entity by name.

        :param str name: Name of the entity.
        :return: Entity schema.
        """
        attribute_type = await self._service.get(name)
        return self._converter_to_extended_schema(attribute_type)

    async def get_list_paginated(
        self,
        params: PaginationParams,
    ) -> AttributeTypePaginationSchema:
        """Get a list of entities with pagination.

        :param PaginationParams params: Pagination parameters.
        :return: Paginated result schema.
        """
        pagination_result = await self._service.get_paginator(params)

        items: list[AttributeTypeSchema] = [
            self._converter_to_schema(item) for item in pagination_result.items
        ]

        return self._pagination_schema(
            metadata=pagination_result.metadata,
            items=items,
        )

    async def update(
        self,
        name: str,
        data: AttributeTypeUpdateSchema,
    ) -> None:
        """Modify an entity.

        :param str name: Name of the entity to modify.
        :param data: Updated data.
        """
        dto = self._converter_update_sch_to_dto(data)
        await self._service.update(name, dto)

    async def delete_bulk(
        self,
        names: LimitedListType,
    ) -> None:
        """Delete multiple entities.

        :param LimitedListType names: Names of entities to delete.
        """
        await self._service.delete_all_by_names(names)
