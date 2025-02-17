"""OAuth modules.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defaultload

from api.auth.utils import get_ip_from_request, get_user_agent_from_request
from config import Settings
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.utils.queries import get_user
from models import Group, User
from security import verify_password

ALGORITHM = "HS256"

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def authenticate_user(
    session: AsyncSession,
    username: str,
    password: str,
) -> User | None:
    """Get user and verify password.

    :param AsyncSession session: sa session
    :param str username: any str
    :param str password: any str
    :return User | None: User model (pydantic)
    """
    user = await get_user(session, username)

    if not user or not user.password or not password:
        return None
    if not verify_password(password, user.password):
        return None
    return user


@inject
async def get_current_user(
    settings: FromDishka[Settings],
    session: FromDishka[AsyncSession],
    session_storage: FromDishka[SessionStorage],
    request: Request,
    response: Response,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
    user_agent: Annotated[str, Depends(get_user_agent_from_request)],
) -> UserSchema:
    """Get current user.

    Fetches the user id associated with the session stored in the
    request's cookies, verifies the session, and returns the user schema.
    Makes a rekey of the session if necessary.

    :param FromDishka[Settings] settings: settings
    :param FromDishka[AsyncSession] session: db session
    :param FromDishka[SessionStorage] session_storage: session storage
    :param Request request: request
    :param Response response: response
    :param Annotated[IPv4Address | IPv6Address] ip: ip address
    :param Annotated[str] user_agent: user agent
    :return UserSchema: user schema
    """
    session_key = request.cookies.get("id", "")
    try:
        user_id = await session_storage.get_user_id(
            settings, session_key, user_agent, str(ip),
        )
    except KeyError as err:
        raise _CREDENTIALS_EXCEPTION from err

    user = await session.scalar(
        select(User)
        .options(
            defaultload(User.groups).selectinload(Group.access_policies))
        .where(User.id == user_id))

    if user is None:
        raise _CREDENTIALS_EXCEPTION

    session_id, _ = session_key.split(".")
    try:
        if await session_storage.check_rekey(
            session_id, settings.SESSION_REKEY_INTERVAL,
        ):
            key = await session_storage.rekey_session(session_id, settings)
            response.set_cookie(
                key="id",
                value=key,
                httponly=True,
                expires=session_storage.key_ttl,
            )
    except KeyError as err:
        raise _CREDENTIALS_EXCEPTION from err

    return await UserSchema.from_db(user, session_id)
