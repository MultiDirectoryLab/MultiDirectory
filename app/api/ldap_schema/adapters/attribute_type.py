"""Attribute Type management routers.

Copyright (c) 2025 MultiFactor
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
    BaseAdapter[AttributeTypeDAO],
    BaseLDAPSchema,
):
    """Attribute Type management routers."""

    _schema = AttributeTypeSchema
    _pagination_schema = AttributeTypePaginationSchema
    _request_schema = AttributeTypeRequestSchema
    _update_schema = AttributeTypeUpdateSchema
    _dto = AttributeTypeDTO
    converter_to_dto = _convert_request_to_dto
    converter_to_schema = _convert_dto_to_schema

    _exceptions_map: dict[type[Exception], int] = {
        AttributeTypeAlreadyExistsError: status.HTTP_409_CONFLICT,
        AttributeTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        AttributeTypeCantModifyError: status.HTTP_403_FORBIDDEN,
    }

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
