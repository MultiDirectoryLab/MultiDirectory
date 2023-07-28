"""Auth api."""

from extra.setup_dev import setup_enviroment
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings, get_settings
from ldap.ldap_responses import LDAPCodes, LDAPResult
from ldap.utils import get_base_dn
from models.database import get_session
from models.ldap3 import CatalogueSetting

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
    setup_already_performed = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == 'defaultNamingContext'),
    )

    if setup_already_performed:
        return LDAPResult(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)

    data = [  # noqa
        {
            "name": "groups",
            "object_class": "container",
            "attributes": {
                "objectClass": ["top"],
                'sAMAccountName': ['groups'],
            },
            "children": [
                {
                    "name": "domain admins",
                    "object_class": "group",
                    "attributes": {
                        "objectClass": ["top"],
                        'groupType': ['-2147483646'],
                        'instanceType': ['4'],
                        'sAMAccountName': ['domain admins'],
                        'sAMAccountType': ['268435456'],
                    },
                },
            ],
        },
        {
            "name": "users",
            "object_class": "organizationalUnit",
            "attributes": {"objectClass": ["top", "container"]},
            "children": [
                {
                    "name": request.username,
                    "object_class": "user",
                    "organizationalPerson": {
                        "sam_accout_name": request.username,
                        "user_principal_name": request.user_principal_name,
                        "mail": request.mail,
                        "display_name": request.display_name,
                        "password": request.password,
                        "groups": ['domain admins'],
                    },
                    "attributes": {"objectClass": [
                        "top", "person",
                        "organizationalPerson", "posixAccount"]},
                },
            ],
        },
    ]

    async with session.begin_nested():
        try:
            await setup_enviroment(session, dn=request.domain, data=data)
        except IntegrityError:
            await session.rollback()
            return LDAPResult(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
        else:
            get_base_dn.cache_clear()
    return LDAPResult(result_code=LDAPCodes.SUCCESS)
