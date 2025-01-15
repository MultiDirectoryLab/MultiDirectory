"""OAuth modules.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Depends, HTTPException, Request, status
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defaultload

from config import Settings
from ldap_protocol.dialogue import SessionStorage, UserSchema
from ldap_protocol.utils.queries import get_user
from models import Group, User
from security import verify_password

ALGORITHM = "HS256"


def get_token(
    request: Request,
    auto_error: bool = True,
) -> str | None:
    """Get token from cookies.

    :param Request request: request
    :param bool auto_error: raise 401 or not, defaults to True
    :param Literal[access_token, refresh_token]
        type_: token type choice, defaults to 'access_token'
    :raises HTTPException: 401
    :return str | None: parsed token
    """
    authorization: str = request.cookies.get("id", "")

    scheme, param = get_authorization_scheme_param(authorization)
    if not authorization or scheme.lower() != "bearer":
        if auto_error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return None
    return param


class OAuth2PasswordBearerWithCookie(OAuth2):
    """Cookie bearer token manager."""

    def __init__(
        self,
        tokenUrl: str,  # noqa
        scheme_name: str | None = None,
        scopes: dict[str, str] | None = None,
        auto_error: bool = True,
    ):
        """Set token params."""
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(
            password={"tokenUrl": tokenUrl, "scopes": scopes},
        )
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> str | None:
        """Accept access token from httpOnly Cookie.

        :param Request request: request
        :param bool auto_error: raise 401 or not, defaults to True
        :param Literal[access_token, refresh_token]
            type_: token type choice, defaults to 'access_token'
        :raises HTTPException: 401
        :return str | None: parsed token
        """
        authorization: str = request.cookies.get("id", "")

        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None
        return param


oauth2 = OAuth2PasswordBearerWithCookie(
    tokenUrl="auth/token/get", auto_error=False,
)

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

    if not user:
        return None
    if not verify_password(password, user.password or ""):
        return None
    return user


@inject
async def get_current_user(  # noqa: D103
    settings: FromDishka[Settings],
    session: FromDishka[AsyncSession],
    session_storage: FromDishka[SessionStorage],
    session_key: Annotated[str, Depends(oauth2)],
) -> UserSchema:
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

    return await UserSchema.from_db(user, session_key)
