"""Session router for handling user sessions."""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import Depends, status
from fastapi.routing import APIRouter

from .adapters.session_gateway import (
    SessionContentResponseSchema,
    SessionFastAPIGateway,
)
from .oauth2 import get_current_user

session_router = APIRouter(
    prefix="/sessions",
    tags=["Session"],
    route_class=DishkaRoute,
    dependencies=[Depends(get_current_user)],
)


@session_router.get("/{upn}")
async def get_user_session(
    upn: str,
    gateway: FromDishka[SessionFastAPIGateway],
) -> dict[str, SessionContentResponseSchema]:
    """Get user (upn, san or dn) data."""
    return await gateway.get_user_sessions(upn)


@session_router.delete("/{upn}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_sessions(
    upn: str,
    gateway: FromDishka[SessionFastAPIGateway],
) -> None:
    """Delete user (upn, san or dn) data."""
    await gateway.delete_user_sessions(upn)


@session_router.delete(
    "/session/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_session(
    session_id: str,
    gateway: FromDishka[SessionFastAPIGateway],
) -> None:
    """Delete current logged in user data."""
    await gateway.delete_session(session_id)
