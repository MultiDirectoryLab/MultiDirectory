"""OAuth modules.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime, timedelta
from typing import Annotated, Literal

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.multifactor import MFA_HTTP_Creds
from ldap_protocol.utils import get_base_dn, get_user
from models.ldap3 import User as DBUser
from security import verify_password

from .schema import User

ALGORITHM = "HS256"

oauth2 = OAuth2PasswordBearer(tokenUrl="auth/token/get", auto_error=False)

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

    try:
        base_dn = await get_base_dn(session)
    except NoResultFound:
        return None

    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return User.from_db(user, access='access', base_dn=base_dn)


def create_token(
    uid: int,
    secret: str,
    expires_minutes: int,
    grant_type: Literal['refresh', 'access'],
    *, extra_data: dict | None = None,
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
    to_encode['uid'] = uid
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire, 'grant_type': grant_type})
    return jwt.encode(to_encode, secret)


async def _get_user_from_token(
    settings: Settings,
    session: AsyncSession,
    token: str,
    mfa_creds: MFA_HTTP_Creds,
) -> User:
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
                algorithms=ALGORITHM)
        except (JWTError, AttributeError):
            raise _CREDENTIALS_EXCEPTION

    user_id: int = int(payload.get("uid"))

    if user_id is None:
        raise _CREDENTIALS_EXCEPTION

    user = await session.get(DBUser, user_id)

    try:
        base_dn = await get_base_dn(session)
    except NoResultFound:
        raise _CREDENTIALS_EXCEPTION

    if user is None:
        raise _CREDENTIALS_EXCEPTION

    return User.from_db(
        user,
        payload.get("grant_type"),
        base_dn,
        payload.get("exp"),
    )


@inject
async def get_current_user(  # noqa: D103
    settings: FromDishka[Settings],
    session: FromDishka[AsyncSession],
    token: Annotated[str, Depends(oauth2)],
    mfa_creds: FromDishka[MFA_HTTP_Creds],
) -> User:
    user = await _get_user_from_token(settings, session, token, mfa_creds)

    if user.access_type not in ('access', 'multifactor'):
        raise _CREDENTIALS_EXCEPTION

    if user.access_type == 'multifactor' and\
            user.exp - settings.MFA_TOKEN_LEEWAY < (
                datetime.utcnow().timestamp()):
        raise _CREDENTIALS_EXCEPTION

    return user


@inject
async def get_current_user_refresh(  # noqa: D103
    settings: FromDishka[Settings],
    session: FromDishka[AsyncSession],
    mfa_creds: FromDishka[MFA_HTTP_Creds],
    token: Annotated[str, Depends(oauth2)],
) -> User:
    user = await _get_user_from_token(settings, session, token, mfa_creds)
    if user.access_type not in ('refresh', 'multifactor'):
        raise _CREDENTIALS_EXCEPTION

    return user
