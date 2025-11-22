"""LDAP Schema routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from annotated_types import Len
from fastapi import Body, Depends
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from api.auth import verify_auth
from enums import ProjectPartCodes
from errors import (
    ERROR_MAP_TYPE,
    BaseErrorTranslator,
    DishkaErrorAwareRoute,
    ErrorStatusCodes,
)
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
    AttributeTypeCantModifyError,
    AttributeTypeNotFoundError,
    EntityTypeAlreadyExistsError,
    EntityTypeCantModifyError,
    EntityTypeNotFoundError,
    ObjectClassAlreadyExistsError,
    ObjectClassCantModifyError,
    ObjectClassNotFoundError,
)

LimitedListType = Annotated[
    list[str],
    Len(min_length=1, max_length=10000),
    Body(embed=True),
]


class LDAPSchemaErrorTranslator(BaseErrorTranslator):
    """LDAP Schema error translator."""

    domain_code = ProjectPartCodes.LDAP_SCHEMA


error_map: ERROR_MAP_TYPE = {
    AttributeTypeAlreadyExistsError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=LDAPSchemaErrorTranslator(),
    ),
    AttributeTypeNotFoundError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=LDAPSchemaErrorTranslator(),
    ),
    AttributeTypeCantModifyError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=LDAPSchemaErrorTranslator(),
    ),
    ObjectClassAlreadyExistsError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=LDAPSchemaErrorTranslator(),
    ),
    ObjectClassNotFoundError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=LDAPSchemaErrorTranslator(),
    ),
    ObjectClassCantModifyError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=LDAPSchemaErrorTranslator(),
    ),
    EntityTypeAlreadyExistsError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=LDAPSchemaErrorTranslator(),
    ),
    EntityTypeNotFoundError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=LDAPSchemaErrorTranslator(),
    ),
    EntityTypeCantModifyError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=LDAPSchemaErrorTranslator(),
    ),
}

ldap_schema_router = ErrorAwareRouter(
    prefix="/schema",
    tags=["Schema"],
    dependencies=[Depends(verify_auth)],
    route_class=DishkaErrorAwareRoute,
)
