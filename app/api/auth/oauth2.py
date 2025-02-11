"""OAuth modules.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defaultload

from config import Settings
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.policies.network_policy import get_user_network_policy
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.utils.queries import get_user
from models import Group, User
from security import verify_password

from .utils import get_ip_from_request

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
async def get_current_user(  # noqa: D103
    settings: FromDishka[Settings],
    session: FromDishka[AsyncSession],
    session_storage: FromDishka[SessionStorage],
    request: Request,
    response: Response,
) -> UserSchema:
    session_key = request.cookies.get("id", "")
    try:
        user_id = await session_storage.get_user_id(settings, session_key)
    except KeyError as err:
        raise _CREDENTIALS_EXCEPTION from err

    user = await session.scalar(
        select(User)
        .options(
            defaultload(User.groups).selectinload(Group.access_policies))
        .where(User.id == user_id))

    if user is None:
        raise _CREDENTIALS_EXCEPTION

    ip = get_ip_from_request(request)
    network_policy = await get_user_network_policy(ip, user, session)
    if network_policy is None:
        raise _CREDENTIALS_EXCEPTION

    session_id, _ = session_key.split(".")
    rekey_is_need = await session_storage.check_rekey(
        session_id, network_policy.session_rekey_interval,
    )

    if rekey_is_need:
        key = await session_storage.rekey_session(session_id, settings)
        response.set_cookie(
            key="id",
            value=key,
            httponly=True,
            expires=session_storage.key_ttl,
        )

    return await UserSchema.from_db(user, session_id)
