from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from config import Settings, get_settings
from models.database import AsyncSession

from .oauth2 import authenticate_user, create_token, get_current_user
from .schema import Token, UserModel

auth_router = APIRouter()


@auth_router.post("/token/get", response_model=Token)
async def login_for_access_token(
    form: OAuth2PasswordRequestForm = Depends(),
    settings: Settings = Depends(get_settings),
    session: AsyncSession = Depends(),
):
    """Get refresh and access token with login.

    :param OAuth2PasswordRequestForm form: password form, defaults to Depends()
    :param Settings settings: app settings, defaults to Depends(get_settings)
    :param AsyncSession session: sa session, defaults to Depends()
    :raises HTTPException: in invalid user
    :return Token: refresh and access token
    """
    user = await authenticate_user(session, form.username, form.password)
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

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"}


@auth_router.post("/token/refresh", response_model=Token)
async def get_refresh_token():
    pass


@auth_router.get("/users/me/", response_model=UserModel)
async def users_me(current_user: UserModel = Depends(get_current_user)):
    return current_user
