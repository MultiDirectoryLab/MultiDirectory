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
from api.ldap_schema.adapters.base_ldap_schema_adapter import (
    BaseLDAPSchemaAdapter,
)
from api.ldap_schema.schema import (
    AttributeTypePaginationSchema,
    AttributeTypeSchema,
    AttributeTypeUpdateSchema,
)
from ldap_protocol.ldap_schema.attribute_type_use_case import (
    AttributeTypeUseCase,
)
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
from ldap_protocol.permissions_checker import ApiPermissionError


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
        is_included_anr=request.is_included_anr,
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


class AttributeTypeFastAPIAdapter(
    BaseAdapter[AttributeTypeUseCase],
    BaseLDAPSchemaAdapter[
        AttributeTypeUseCase,
        AttributeTypeSchema,
        AttributeTypeUpdateSchema,
        AttributeTypePaginationSchema,
        AttributeTypeDTO,
    ],
):
    """Attribute Type management routers."""

    _pagination_schema = AttributeTypePaginationSchema

    _converter_to_dto = staticmethod(_convert_schema_to_dto)
    _converter_to_schema = staticmethod(_convert_dto_to_schema)
    _converter_update_sch_to_dto = staticmethod(_convert_update_uschema_to_dto)

    _exceptions_map: dict[type[Exception], int] = {
        AttributeTypeAlreadyExistsError: status.HTTP_409_CONFLICT,
        AttributeTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        AttributeTypeCantModifyError: status.HTTP_403_FORBIDDEN,
        ApiPermissionError: status.HTTP_403_FORBIDDEN,
    }
