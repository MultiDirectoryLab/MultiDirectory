"""Session router for handling user sessions."""

from dishka import FromDishka
from fastapi import Depends, status
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from enums import ProjectPartCodes
from errors import (
    ERROR_MAP_TYPE,
    BaseErrorTranslator,
    DishkaErrorAwareRoute,
    ErrorStatusCodes,
)
from ldap_protocol.session_storage.exceptions import SessionUserNotFoundError

from .adapters.session_gateway import (
    SessionContentResponseSchema,
    SessionFastAPIGateway,
)
from .utils import verify_auth


class SessionErrorTranslator(BaseErrorTranslator):
    """Session error translator."""

    domain_code = ProjectPartCodes.SESSION


error_map: ERROR_MAP_TYPE = {
    SessionUserNotFoundError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=SessionErrorTranslator(),
    ),
}

session_router = ErrorAwareRouter(
    prefix="/sessions",
    tags=["Session"],
    route_class=DishkaErrorAwareRoute,
    dependencies=[Depends(verify_auth)],
)


@session_router.get("/{upn}", error_map=error_map)
async def get_user_session(
    upn: str,
    gateway: FromDishka[SessionFastAPIGateway],
) -> dict[str, SessionContentResponseSchema]:
    """Get user (upn, san or dn) data."""
    return await gateway.get_user_sessions(upn)


@session_router.delete(
    "/{upn}",
    status_code=status.HTTP_204_NO_CONTENT,
    error_map=error_map,
)
async def delete_user_sessions(
    upn: str,
    gateway: FromDishka[SessionFastAPIGateway],
) -> None:
    """Delete user (upn, san or dn) data."""
    await gateway.delete_user_sessions(upn)


@session_router.delete(
    "/session/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    error_map=error_map,
)
async def delete_session(
    session_id: str,
    gateway: FromDishka[SessionFastAPIGateway],
) -> None:
    """Delete current logged in user data."""
    await gateway.delete_session(session_id)
