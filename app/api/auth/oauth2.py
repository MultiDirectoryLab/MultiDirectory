from datetime import datetime, timedelta
from typing import Literal

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt

from config import Settings, get_settings
from ldap.utils import get_user
from models.database import AsyncSession, get_session
from models.ldap3 import User
from security import verify_password

from .schema import UserModel

ALGORITHM = "HS256"


oauth2 = OAuth2AuthorizationCodeBearer(
    authorizationUrl="users",
    tokenUrl="token",
    refreshUrl="refresh",
)


async def authenticate_user(
    session: AsyncSession,
    username: str,
    password: str,
) -> UserModel | None:
    user = await get_user(session, username)
    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return UserModel.from_db(user)


def create_token(
    data: dict,
    secret: str,
    expires_minutes: int,
    token_type: Literal['refresh', 'access'],
) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire, 'type': token_type})
    return jwt.encode(to_encode, secret, algorithm=ALGORITHM)


async def get_current_user(
    settings: Settings = Depends(get_settings),
    session: AsyncSession = Depends(get_session),
    token: str = Depends(oauth2),
) -> UserModel:
    """Get user from jwt.

    :param Settings settings: app settings, defaults to Depends(get_settings)
    :param AsyncSession session: sa session, defaults to Depends(get_session)
    :param str token: oauth2 obj, defaults to Depends(oauth2)
    :raises credentials_exception: 401
    :return UserModel: user for api response
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await session.get(User, user_id)
    if user is None:
        raise credentials_exception

    return UserModel.from_db(user)
