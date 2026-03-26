"""LDF version API routes."""

from fastapi import Depends, status
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from api.auth.utils import verify_auth
from api.error_routing import (
    ERROR_MAP_TYPE,
    DishkaErrorAwareRoute,
    DomainErrorTranslator,
)
from enums import DomainCodes
from ldap_protocol.ldif_directory_exchange.ldf_version.exceptions import (
    LdfVersionAlreadyExistsError,
    LdfVersionNotFoundError,
)

translator = DomainErrorTranslator(DomainCodes.LDF)

error_map: ERROR_MAP_TYPE = {
    LdfVersionAlreadyExistsError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    LdfVersionNotFoundError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
}

ldf_router = ErrorAwareRouter(
    prefix="/ldf",
    tags=["LDF"],
    dependencies=[Depends(verify_auth)],
    route_class=DishkaErrorAwareRoute,
)
