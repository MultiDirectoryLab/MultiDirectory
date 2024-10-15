"""OAuth modules.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime, timedelta
from typing import Annotated, Literal

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Depends, HTTPException, Request, status
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import Settings
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.multifactor import MFA_HTTP_Creds
from ldap_protocol.utils.queries import get_user
from models import Group, User
from security import verify_password

ALGORITHM = "HS256"


def get_token(
    request: Request,
    auto_error: bool = True,
    type_: Literal["access_token", "refresh_token"] = "access_token",
) -> str | None:
    """Get token from cookies.

    :param Request request: request
    :param bool auto_error: raise 401 or not, defaults to True
    :param Literal[access_token, refresh_token]
        type_: token type choice, defaults to 'access_token'
    :raises HTTPException: 401
    :return str | None: parsed token
    """
    authorization: str = request.cookies.get(type_, "")

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
        """Accept access token from httpOnly Cookie."""
        return get_token(request, self.auto_error)


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


def create_token(
    uid: int,
    secret: str,
    expires_minutes: int,
    grant_type: Literal["refresh", "access"],
    *,
    extra_data: dict | None = None,
) -> str:
    """Create jwt token.

    :param int uid: user id
    :param dict data: data dict
    :param str secret: secret key
    :param int expires_minutes: exire time in minutes
    :param Literal[refresh, access] grant_type: grant type flag
    :return str: jwt token
    """
    if not extra_data:
        extra_data = {}

    to_encode = extra_data.copy()
    to_encode["uid"] = uid
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire, "grant_type": grant_type})
    return jwt.encode(to_encode, secret)


async def get_user_from_token(
    settings: Settings,
    session: AsyncSession,
    token: str,
    mfa_creds: MFA_HTTP_Creds,
) -> UserSchema:
    """Get user from jwt.

    :param Settings settings: app settings
    :param AsyncSession session: sa session
    :param str token: oauth2 obj
    :raises _CREDENTIALS_EXCEPTION: 401
    :return User: user for api response
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=ALGORITHM)
    except (JWTError, AttributeError):
        if not mfa_creds:
            raise _CREDENTIALS_EXCEPTION

        try:  # retry with mfa secret
            payload = jwt.decode(
                token,
                mfa_creds.secret,
                audience=mfa_creds.key,
                algorithms=ALGORITHM,
            )
        except (JWTError, AttributeError):
            raise _CREDENTIALS_EXCEPTION

    user_id: int = int(payload.get("uid"))

    if user_id is None:
        raise _CREDENTIALS_EXCEPTION

    user = await session.scalar(
        select(User)
        .options(
            selectinload(User.groups).selectinload(Group.access_policies))
        .where(User.id == user_id))

    if user is None:
        raise _CREDENTIALS_EXCEPTION

    return UserSchema.from_db(
        user,
        payload.get("grant_type"),
        payload.get("exp"),
    )


@inject
async def get_current_user(  # noqa: D103
    settings: FromDishka[Settings],
    session: FromDishka[AsyncSession],
    token: Annotated[str, Depends(oauth2)],
    mfa_creds: FromDishka[MFA_HTTP_Creds],
) -> UserSchema:
    user = await get_user_from_token(settings, session, token, mfa_creds)

    if user.access_type not in ("access", "multifactor"):
        raise _CREDENTIALS_EXCEPTION

    if (
        user.access_type == "multifactor"
        and user.exp - settings.MFA_TOKEN_LEEWAY
        < (datetime.utcnow().timestamp())
    ):
        raise _CREDENTIALS_EXCEPTION

    return user
