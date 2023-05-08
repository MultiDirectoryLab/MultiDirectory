from datetime import datetime, timedelta
from typing import Literal

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from config import Settings, get_settings
from ldap.utils import get_user
from models.database import AsyncSession, get_session
from models.ldap3 import User as DBUser
from security import verify_password

from .schema import User

ALGORITHM = "HS256"


oauth2 = OAuth2PasswordBearer(tokenUrl="auth/token/get", auto_error=False)


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
    if not verify_password(password, user.password):
        return None
    return User.from_db(user)


def create_token(
    data: dict,
    secret: str,
    expires_minutes: int,
    grant_type: Literal['refresh', 'access'],
) -> str:
    """Create jwt token.

    :param dict data: data dict
    :param str secret: secret key
    :param int expires_minutes: exire time in minutes
    :param Literal[refresh, access] grant_type: grant type flag
    :return str: jwt token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire, 'grant_type': grant_type})
    return jwt.encode(to_encode, secret, algorithm=ALGORITHM)


async def get_user_from_token(
    settings: Settings = Depends(get_settings),
    session: AsyncSession = Depends(get_session),
    token: str = Depends(oauth2),
    grant_type: Literal['access', 'refresh'] = 'access',
) -> User:
    """Get user from jwt.

    :param Settings settings: app settings, defaults to Depends(get_settings)
    :param AsyncSession session: sa session, defaults to Depends(get_session)
    :param str token: oauth2 obj, defaults to Depends(oauth2)
    :raises credentials_exception: 401
    :return User: user for api response
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=ALGORITHM)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    if payload.get("grant_type") != grant_type:
        raise credentials_exception

    user = await session.get(DBUser, int(user_id))
    if user is None:
        raise credentials_exception

    return User.from_db(user)


async def get_current_user(  # noqa: D103
    settings: Settings = Depends(get_settings),
    session: AsyncSession = Depends(get_session),
    token: str = Depends(oauth2),
) -> User:
    return await get_user_from_token(settings, session, token, 'access')


async def get_current_user_or_none(  # noqa: D103
    settings: Settings = Depends(get_settings),
    session: AsyncSession = Depends(get_session),
    token: str = Depends(oauth2),
) -> User | None:
    try:
        return await get_user_from_token(settings, session, token, 'access')
    except Exception:
        return None


async def get_current_user_refresh(  # noqa: D103
    settings: Settings = Depends(get_settings),
    session: AsyncSession = Depends(get_session),
    token: str = Depends(oauth2),
) -> User:
    return await get_user_from_token(settings, session, token, 'refresh')
