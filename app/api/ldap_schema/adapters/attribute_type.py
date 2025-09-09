"""Attribute Type management routers.

Copyright (c) 2025 MultiFactor
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
    AttributeTypePaginationSchema,
    AttributeTypeRequestSchema,
    AttributeTypeSchema,
    AttributeTypeUpdateSchema,
)
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.constants import (
    DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM,
    DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
    DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
    AttributeTypeCantModifyError,
    AttributeTypeNotFoundError,
)
from ldap_protocol.utils.pagination import PaginationParams


def make_attribute_type_request_dto(
    request: AttributeTypeRequestSchema,
) -> AttributeTypeDTO:
    """Convert AttributeTypeRequestSchema to AttributeTypeDTO."""
    return AttributeTypeDTO(
        oid=request.oid,
        name=request.name,
        syntax=DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
        single_value=request.single_value,
        no_user_modification=DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
        is_system=DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM,
    )


def make_attribute_type_schema(dto: AttributeTypeDTO) -> AttributeTypeSchema:
    """Convert AttributeTypeDTO to AttributeTypeSchema."""
    return AttributeTypeSchema(
        id=dto.get_id(),
        oid=dto.oid,
        name=dto.name,
        syntax=dto.syntax,
        single_value=dto.single_value,
        no_user_modification=dto.no_user_modification,
        is_system=dto.is_system,
    )


_convert_request_to_dto = get_converter(
    AttributeTypeRequestSchema,
    AttributeTypeDTO,
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
    AttributeTypeDTO,
    AttributeTypeSchema,
    recipe=[
        link_function(make_attribute_type_schema, P[AttributeTypeSchema]),
    ],
)


class AttributeTypeFastAPIAdapter(
    BaseLDAPSchemaFastAPIAdapter[
        AttributeTypeDAO,
        AttributeTypeSchema,
        AttributeTypePaginationSchema,
        AttributeTypeRequestSchema,
        AttributeTypeUpdateSchema,
        AttributeTypeDTO,
    ],
):
    """Attribute Type management routers."""

    _exceptions_map: dict[type[Exception], int] = {
        AttributeTypeAlreadyExistsError: status.HTTP_409_CONFLICT,
        AttributeTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        AttributeTypeCantModifyError: status.HTTP_403_FORBIDDEN,
    }

    def _get_converter(self) -> tuple[Callable, Callable]:
        """Get converter functions for AttributeType schema <-> DTO."""
        return (
            _convert_dto_to_schema,
            _convert_request_to_dto,
        )

    async def create(
        self,
        request_data: AttributeTypeRequestSchema,
    ) -> None:
        """Create a new Attribute Type.

        :param AttributeTypeRequestSchema request_data:
            Data for creating Attribute Type.
        :return None.
        """
        dto = _convert_request_to_dto(request_data)
        await self._service.create(
            dto,
        )

    async def get(
        self,
        attribute_type_name: str,
    ) -> AttributeTypeSchema:
        """Get a single Attribute Type by name."""
        attribute_type = await self._service.get_one_by_name(
            attribute_type_name,
        )
        return AttributeTypeSchema.model_validate(
            attribute_type,
            from_attributes=True,
        )

    async def get_list_paginated(
        self,
        params: PaginationParams,
    ) -> AttributeTypePaginationSchema:
        """Get a list of Attribute Types with pagination."""
        pagination_result = await self._service.get_paginator(params)
        items = [
            AttributeTypeSchema.model_validate(
                item,
                from_attributes=True,
            )
            for item in pagination_result.items
        ]
        return AttributeTypePaginationSchema(
            metadata=pagination_result.metadata,
            items=items,
        )

    async def update(
        self,
        attribute_type_name: str,
        request_data: AttributeTypeUpdateSchema,
    ) -> None:
        """Modify an Attribute Type."""
        attribute_type = await self._service.get_one_by_name(
            attribute_type_name,
        )
        await self._service.update(
            _id=attribute_type.get_id(),
            dto=AttributeTypeDTO(
                id=attribute_type.get_id(),
                oid=attribute_type.oid,
                name=attribute_type.name,
                syntax=DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
                single_value=request_data.single_value,
                no_user_modification=DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
                is_system=attribute_type.is_system,
            ),
        )

    async def delete_bulk(
        self,
        attribute_types_names: LimitedListType,
    ) -> None:
        """Delete bulk Attribute Types."""
        await self._service.delete_all_by_names(attribute_types_names)
