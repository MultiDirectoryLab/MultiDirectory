"""Auth api."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings, get_settings
from models.database import get_session

from .oauth2 import authenticate_user, create_token, get_current_user
from .schema import Login, Token, UserModel

auth_router = APIRouter(prefix='/auth')


@auth_router.post("/token/get")
async def login_for_access_token(
    form: Login,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Token:
    """Get refresh and access token with login.

    :param Login form: password form, defaults to Depends()
    :param Settings settings: app settings, defaults to Depends(get_settings)
    :param AsyncSession session: sa session, defaults to Depends()
    :raises HTTPException: in invalid user
    :return Token: refresh and access token
    """
    user = await authenticate_user(session, form.name, form.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_token(  # noqa: S106
        data={"sub": user.id},
        secret=settings.SECRET_KEY,
        expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        token_type='access',
    )

    refresh_token = create_token(  # noqa: S106
        data={"sub": user.id},
        secret=settings.SECRET_KEY,
        expires_minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES,
        token_type='refresh',
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        type="bearer",
    )


@auth_router.post("/token/refresh")
async def get_refresh_token(current_user: UserModel = Depends(get_current_user)) -> Token:
    pass


@auth_router.get("/users/me/")
async def users_me(current_user: UserModel = Depends(get_current_user)) -> UserModel:
    return current_user
