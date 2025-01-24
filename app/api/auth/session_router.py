"""Session router for handling user sessions."""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import Depends
from fastapi.routing import APIRouter

from ldap_protocol.session_storage import SessionStorage

from .oauth2 import get_current_user
from .schema import SessionContentSchema

session_router = APIRouter(
    prefix="/session",
    tags=["Session"],
    route_class=DishkaRoute,
    dependencies=[Depends(get_current_user)],
)


@session_router.get("/{user_id}")
async def get_user_session(
    user_id: int,
    storage: FromDishka[SessionStorage],
) -> dict[str, SessionContentSchema]:
    """Get current logged in user data."""
    return await storage.get_user_sessions(user_id)


@session_router.delete("/{user_id}")
async def delete_user_sessions(
    user_id: int,
    storage: FromDishka[SessionStorage],
) -> None:
    """Delete current logged in user data."""
    await storage.clear_user_sessions(user_id)


@session_router.delete("/{session_id}")
async def delete_session(
    session_id: str,
    storage: FromDishka[SessionStorage],
) -> None:
    """Delete current logged in user data."""
    await storage.delete_user_session(session_id)
