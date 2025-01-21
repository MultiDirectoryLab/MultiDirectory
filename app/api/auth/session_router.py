"""Session router for handling user sessions."""

from dishka import FromDishka
from fastapi import Depends
from fastapi.routing import APIRouter

from ldap_protocol.dialogue import SessionStorage

from .oauth2 import get_current_user

session_router = APIRouter(
    prefix="/session",
    tags=["Session"],
    dependencies=[Depends(get_current_user)],
)


@session_router.get("/{user_id}")
async def get_user_session(
    user_id: int,
    storage: FromDishka[SessionStorage],
) -> dict[str, dict[str, str]]:
    """Get current logged in user data."""
    keys = await storage.get_user_sessions(user_id)
    return {key: await storage.get(key) for key in keys}


@session_router.delete("/{user_id}")
async def delete_user_session(
    user_id: int,
    storage: FromDishka[SessionStorage],
) -> None:
    """Delete current logged in user data."""
    await storage.clear_user_sessions(user_id)
