from datetime import datetime, timedelta
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from config import Settings
from ldap.utils import get_user
from models.database import AsyncSession

from .schema import UserModel

ALGORITHM = "HS256"


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_user = OAuth2AuthorizationCodeBearer(
    authorizationUrl="users", tokenUrl="token", refreshUrl="refresh")


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str):
    return pwd_context.hash(password)


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
    session: AsyncSession,
    settings: Settings,
    token: str = Depends(oauth2_user),
) -> UserModel:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await get_user(session, name=username)
    if user is None:
        raise credentials_exception

    return UserModel.from_db(user)
