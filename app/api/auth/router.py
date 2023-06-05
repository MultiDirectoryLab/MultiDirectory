"""Auth api."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings, get_settings
from ldap.ldap_responses import LDAPCodes, LDAPResult
from models.database import get_session
from models.ldap3 import Attribute, CatalogueSetting, Directory
from models.ldap3 import User as DBUser
from security import get_password_hash

from .oauth2 import (
    authenticate_user,
    create_token,
    get_current_user,
    get_current_user_refresh,
    oauth2,
)
from .schema import OAuth2Form, SetupRequest, Token, User

auth_router = APIRouter(prefix='/auth')


@auth_router.post("/token/get")
async def login_for_access_token(
    form: OAuth2Form = Depends(),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Token:
    """Get refresh and access token on login.

    :param OAuth2PasswordRequestForm: password form
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
        data={"sub": str(user.id)},
        secret=settings.SECRET_KEY,
        expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        grant_type='access',
    )

    refresh_token = create_token(  # noqa: S106
        data={"sub": str(user.id)},
        secret=settings.SECRET_KEY,
        expires_minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES,
        grant_type='refresh',
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        type="bearer",
    )


@auth_router.post("/token/refresh")
async def get_refresh_token(
    user: User = Depends(get_current_user_refresh),
    settings: Settings = Depends(get_settings),
    token: str = Depends(oauth2),
) -> Token:
    """Grant access token with refresh.

    :param User user: current user from refresh token
    :param Settings settings: app settings
    :param str token: refresh token
    :return Token: refresh and access token
    """
    access_token = create_token(  # noqa: S106
        data={"sub": str(user.id)},
        secret=settings.SECRET_KEY,
        expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        grant_type='access',
    )
    return Token(
        access_token=access_token,
        refresh_token=token,
        type="bearer",
    )


@auth_router.get("/me")
async def users_me(user: User = Depends(get_current_user)) -> User:
    """Get current user."""
    return user


@auth_router.get('/setup')
async def check_setup(session: AsyncSession = Depends(get_session)) -> bool:
    """Check if initial setup needed."""
    return bool(await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == 'defaultNamingContext'),
    ))


@auth_router.post('/setup')
async def first_setup(
    request: SetupRequest,
    session: AsyncSession = Depends(get_session),
) -> LDAPResult:
    """Perform initial setup."""
    setup_available = bool(await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == 'defaultNamingContext'),
    ))

    if not setup_available:
        return LDAPResult(resultCode=LDAPCodes.ENTRY_ALREADY_EXISTS)

    domain = request.domain.replace('http://', '').replace('https://', '')

    directory = Directory(object_class='user', name=request.username)
    path = directory.create_path()
    attrs = []

    object_classes = (
        'user', 'top', 'person', 'organizationalPerson', 'posixAccount')

    for oc in object_classes:
        attrs.append(
            Attribute(name='objectClass', value=oc, directory=directory))

    user = DBUser(
        sam_accout_name=request.username,
        display_name=request.display_name,
        user_principal_name=request.user_principal_name,
        mail=request.mail,
        password=get_password_hash(request.password),
        directory=directory,
    )
    catalogue = CatalogueSetting(name='defaultNamingContext', value=domain)

    async with session.begin_nested():
        session.add_all([catalogue, directory, user] + attrs)
        directory.paths.append(path)
        await session.commit()

    return LDAPResult(resultCode=LDAPCodes.SUCCESS)
