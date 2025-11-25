"""LDAP Schema routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from annotated_types import Len
from fastapi import Body, Depends, status
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from api.auth.utils import verify_auth
from api.error_routing import (
    ERROR_MAP_TYPE,
    DishkaErrorAwareRoute,
    DomainErrorTranslator,
)
from enums import DoaminCodes
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

translator = DomainErrorTranslator(domain_code=DoaminCodes.LDAP_SCHEMA)


error_map: ERROR_MAP_TYPE = {
    AttributeTypeAlreadyExistsError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    AttributeTypeNotFoundError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    AttributeTypeCantModifyError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    ObjectClassAlreadyExistsError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    ObjectClassNotFoundError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    ObjectClassCantModifyError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    EntityTypeAlreadyExistsError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    EntityTypeNotFoundError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    EntityTypeCantModifyError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
}

ldap_schema_router = ErrorAwareRouter(
    prefix="/schema",
    tags=["Schema"],
    dependencies=[Depends(verify_auth)],
    route_class=DishkaErrorAwareRoute,
)
