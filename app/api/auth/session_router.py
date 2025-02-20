"""Session router for handling user sessions."""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import Depends, HTTPException, status
from fastapi.routing import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.utils.queries import get_user_by_upn

from .oauth2 import get_current_user
from .schema import SessionContentSchema

session_router = APIRouter(
    prefix="/sessions",
    tags=["Session"],
    route_class=DishkaRoute,
    dependencies=[Depends(get_current_user)],
)


@session_router.get("/{upn}")
async def get_user_session(
    upn: str,
    storage: FromDishka[SessionStorage],
    session: FromDishka[AsyncSession],
) -> dict[str, SessionContentSchema]:
    """Get current logged in user data."""
    user = await get_user_by_upn(session, upn)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return await storage.get_user_sessions(user.id)


@session_router.delete("/{upn}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_sessions(
    upn: str,
    storage: FromDishka[SessionStorage],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete current logged in user data."""
    user = await get_user_by_upn(session, upn)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    await storage.clear_user_sessions(user.id)


@session_router.delete(
    "/session/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_session(
    session_id: str, storage: FromDishka[SessionStorage]
) -> None:
    """Delete current logged in user data."""
    await storage.delete_user_session(session_id)
