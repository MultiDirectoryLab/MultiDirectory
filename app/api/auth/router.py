"""Auth api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from extra.setup_dev import setup_enviroment
from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import Settings
from ldap_protocol.access_policy import create_policy
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.multifactor import MultifactorAPI
from ldap_protocol.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.utils import get_base_directories, set_last_logon_user
from models.ldap3 import CatalogueSetting, Directory, Group
from models.ldap3 import User as DBUser
from security import get_password_hash

from .oauth2 import (
    authenticate_user,
    create_token,
    get_current_user,
    get_current_user_refresh,
    get_user,
    oauth2,
)
from .schema import OAuth2Form, SetupRequest, Token

auth_router = APIRouter(prefix='/auth', tags=['Auth'])


@auth_router.post("/token/get")
@inject
async def login_for_access_token(
    form: Annotated[OAuth2Form, Depends()],
    session: FromDishka[AsyncSession],
    settings: FromDishka[Settings],
) -> Token:
    """Get refresh and access token on login.

    - **username**: username formats:
    `DN`, `userPrincipalName`, `saMAccountName`

    \f
    :param OAuth2PasswordRequestForm: password form
    :raises HTTPException: in invalid user
    :return Token: refresh and access token
    """  # noqa: D205, D301
    user = await authenticate_user(session, form.username, form.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    admin_group = await session.scalar(
        select(Group)
        .join(Group.users)
        .filter(DBUser.id == user.id, Directory.name == "domain admins"))

    if not admin_group:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    mfa_enabled = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name.in_(['mfa_key', 'mfa_secret'])))

    if mfa_enabled:
        raise HTTPException(
            status.HTTP_426_UPGRADE_REQUIRED, detail='Requires MFA connect')

    access_token = create_token(  # noqa: S106
        uid=user.id,
        secret=settings.SECRET_KEY,
        expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        grant_type='access',
    )

    refresh_token = create_token(  # noqa: S106
        uid=user.id,
        secret=settings.SECRET_KEY,
        expires_minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES,
        grant_type='refresh',
    )

    await set_last_logon_user(user, session, settings.TIMEZONE)

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        type="bearer",
    )


@auth_router.post("/token/refresh")
@inject
async def renew_tokens(
    user: Annotated[UserSchema, Depends(get_current_user_refresh)],
    token: Annotated[str, Depends(oauth2)],
    *,
    mfa: FromDishka[MultifactorAPI],
    settings: FromDishka[Settings],
) -> Token:
    """Grant new access token with refresh token.

    - **Authorization**: requires refresh bearer token in headers:

    `Authorization: Bearer refresh_token`

    \f
    :param User user: current user from refresh token
    :param Settings settings: app settings
    :param str token: refresh token
    :return Token: refresh and access token
    """  # noqa: D205, D301
    if user.access_type == 'multifactor':
        if not mfa:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY)

        access_token = await mfa.refresh_token(token)
        token = access_token

    else:
        access_token = create_token(  # noqa: S106
            uid=user.id,
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
async def users_me(
        user: Annotated[UserSchema, Depends(get_current_user)]) -> UserSchema:
    """Get current logged in user data."""
    return user


@auth_router.patch(
    '/user/password',
    status_code=200,
    dependencies=[Depends(get_current_user)])
@inject
async def password_reset(
    identity: Annotated[str, Body(example='admin')],
    new_password: Annotated[str, Body(example='password')],
    session: FromDishka[AsyncSession],
    kadmin: FromDishka[AbstractKadmin],
) -> None:
    """Reset user's (entry) password.

    - **identity**: user identity, any
    `userPrincipalName`, `saMAccountName` or `DN`
    - **new_password**: password to set
    \f
    :raises HTTPException: 404 if user not found
    :return bool: status
    """
    user = await get_user(session, identity)

    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    policy = await PasswordPolicySchema.get_policy_settings(session)
    errors = await policy.validate_password_with_policy(new_password, user)

    if errors:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=errors,
        )

    user.password = get_password_hash(new_password)

    try:
        await kadmin.create_or_update_principal_pw(
            user.get_upn_prefix(), new_password)
    except KRBAPIError:
        raise HTTPException(
            status.HTTP_424_FAILED_DEPENDENCY,
            'Failed kerberos password update',
        )

    await post_save_password_actions(user, session)
    await session.commit()


@auth_router.get('/setup')
@inject
async def check_setup(
        session: FromDishka[AsyncSession]) -> bool:
    """Check if initial setup needed.

    True if setup already complete, False if setup is needed.
    """
    return await session.scalar(select(
        exists(Directory)
        .where(Directory.parent_id.is_(None))))


@auth_router.post(
    '/setup', status_code=status.HTTP_200_OK,
    responses={423: {"detail": 'Locked'}})
@inject
async def first_setup(
    request: SetupRequest,
    session: FromDishka[AsyncSession],
) -> None:
    """Perform initial setup."""
    setup_already_performed = await session.scalar(
        select(Directory)
        .filter(Directory.parent_id.is_(None)),
    )

    if setup_already_performed:
        raise HTTPException(status.HTTP_423_LOCKED)

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
                        "objectClass": ["top", 'posixGroup'],
                        'groupType': ['-2147483646'],
                        'instanceType': ['4'],
                        'sAMAccountName': ['domain admins'],
                        'sAMAccountType': ['268435456'],
                    },
                    "objectSid": 512,
                },
                {
                    "name": "domain users",
                    "object_class": "group",
                    "attributes": {
                        "objectClass": ["top", 'posixGroup'],
                        'groupType': ['-2147483646'],
                        'instanceType': ['4'],
                        'sAMAccountName': ['users'],
                        'sAMAccountType': ['268435456'],
                    },
                    "objectSid": 513,
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
                    "attributes": {
                        "objectClass": [
                            "top", "person",
                            "organizationalPerson",
                            "posixAccount",
                            "shadowAccount",
                        ],
                        "loginShell": ["/bin/bash"],
                        "uidNumber": ["1000"],
                        "gidNumber": ["10000"],
                    },
                    "objectSid": 500,
                },
            ],
        },
    ]

    async with session.begin_nested():
        try:
            await setup_enviroment(session, dn=request.domain, data=data)

            await session.flush()

            default_pwd_policy = PasswordPolicySchema()
            errors = await default_pwd_policy.validate_password_with_policy(
                request.password, None)

            if errors:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=errors,
                )

            await default_pwd_policy.create_policy_settings(session)

            domain: Directory = await session.scalar(
                select(Directory)
                .options(joinedload(Directory.path))
                .filter(Directory.parent_id.is_(None)),
            )

            await create_policy(
                name='Root Access Policy',
                can_add=True,
                can_modify=True,
                can_read=True,
                can_delete=True,
                grant_dn=domain.path_dn,
                groups=["cn=domain admins,cn=groups," + domain.path_dn],
                session=session,
            )

            await session.commit()

        except IntegrityError:
            await session.rollback()
            raise HTTPException(status.HTTP_423_LOCKED)
        else:
            get_base_directories.cache_clear()
