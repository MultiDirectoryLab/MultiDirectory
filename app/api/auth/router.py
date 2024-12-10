"""Auth api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import secrets
from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from extra.setup_dev import setup_enviroment
from ldap_protocol.access_policy import create_access_policy
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.multifactor import MFA_HTTP_Creds, MultifactorAPI
from ldap_protocol.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.user_account_control import (
    UserAccountControlFlag,
    get_check_uac,
)
from ldap_protocol.utils.helpers import ft_now
from ldap_protocol.utils.queries import (
    get_base_directories,
    get_user_network_policy,
    set_last_logon_user,
)
from models import Directory, Group, PolicyProtocol, User
from security import get_password_hash

from .oauth2 import (
    authenticate_user,
    create_token,
    get_current_user,
    get_token,
    get_user,
    get_user_from_token,
)
from .schema import REFRESH_PATH, OAuth2Form, SetupRequest
from .utils import get_ip_from_request

auth_router = APIRouter(prefix="/auth", tags=["Auth"])


@auth_router.post("/token/get")
@inject
async def login_for_access_token(
    form: Annotated[OAuth2Form, Depends()],
    session: FromDishka[AsyncSession],
    settings: FromDishka[Settings],
    mfa_http_creds: FromDishka[MFA_HTTP_Creds],
    request: Request,
    response: Response,
) -> None:
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

    query = (  # noqa: ECE001
        select(Group)
        .join(Group.users)
        .join(Group.directory)
        .filter(User.id == user.id, Directory.name == "domain admins")
        .exists())

    is_part_of_admin_group = (await session.scalars(select(query))).one()

    if not is_part_of_admin_group:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    uac_check = await get_check_uac(session, user.directory_id)

    if uac_check(UserAccountControlFlag.ACCOUNTDISABLE):
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    if user.is_expired():
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    ip = get_ip_from_request(request)
    if not ip:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    network_policy = await get_user_network_policy(
        ip,
        user,
        PolicyProtocol.WebAdminAPI,
        session,
    )

    if network_policy is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    if mfa_http_creds:
        raise HTTPException(
            status.HTTP_426_UPGRADE_REQUIRED,
            detail="Requires MFA connect",
        )

    access_token = create_token(  # noqa: S106
        uid=user.id,
        secret=settings.SECRET_KEY,
        expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        grant_type="access",
        extra_data={"uuid": secrets.token_urlsafe(8)},
    )

    refresh_token = create_token(  # noqa: S106
        uid=user.id,
        secret=settings.SECRET_KEY,
        expires_minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES,
        grant_type="refresh",
        extra_data={"uuid": secrets.token_urlsafe(8)},
    )

    await set_last_logon_user(user, session, settings.TIMEZONE)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
    )
    response.set_cookie(
        key="refresh_token",
        value=f"Bearer {refresh_token}",
        httponly=True,
        path=REFRESH_PATH,
    )


@auth_router.post("/token/refresh", response_class=Response)
@inject
async def renew_tokens(
    request: Request,
    mfa: FromDishka[MultifactorAPI],
    settings: FromDishka[Settings],
    response: Response,
    session: FromDishka[AsyncSession],
    mfa_creds: FromDishka[MFA_HTTP_Creds],
) -> None:
    """Grant new access token with refresh token.

    - **Authorization**: requires refresh bearer token in headers:

    `Authorization: Bearer refresh_token`

    \f
    :param User user: current user from refresh token
    :param Settings settings: app settings
    :param str token: refresh token
    :return Token: refresh and access token
    """
    token: str = get_token(request, type_="refresh_token")  # type: ignore
    user = await get_user_from_token(settings, session, token, mfa_creds)

    if user.access_type == "multifactor":
        if not mfa:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY)

        access_token = await mfa.refresh_token(token)

        response.set_cookie(
            key="refresh_token",
            value=f"Bearer {access_token}",
            httponly=True,
            path=REFRESH_PATH,
        )

    elif user.access_type == "refresh":
        access_token = create_token(  # noqa: S106
            uid=user.id,
            secret=settings.SECRET_KEY,
            expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            grant_type="access",
            extra_data={"uuid": secrets.token_urlsafe(8)},
        )
    else:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)

    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
    )


@auth_router.get("/me")
async def users_me(
    user: Annotated[UserSchema, Depends(get_current_user)],
) -> UserSchema:
    """Get current logged in user data."""
    return user


@auth_router.delete("/token/refresh", response_class=Response)
def logout(response: Response) -> None:
    """Delete token cookies."""
    response.delete_cookie("access_token", httponly=True)
    response.delete_cookie(
        "refresh_token",
        path="/api/auth/token/refresh",
        httponly=True,
    )


@auth_router.patch(
    "/user/password",
    status_code=200,
    dependencies=[Depends(get_current_user)],
)
@inject
async def password_reset(
    identity: Annotated[str, Body(examples=["admin"])],
    new_password: Annotated[str, Body(examples=["password"])],
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

    policy = await PasswordPolicySchema.get_policy_settings(session, kadmin)
    errors = await policy.validate_password_with_policy(new_password, user)

    if errors:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=errors,
        )

    user.password = get_password_hash(new_password)

    try:
        await kadmin.create_or_update_principal_pw(
            user.get_upn_prefix(),
            new_password,
        )
    except KRBAPIError:
        raise HTTPException(
            status.HTTP_424_FAILED_DEPENDENCY,
            "Failed kerberos password update",
        )

    await post_save_password_actions(user, session)
    await session.commit()


@auth_router.get("/setup")
@inject
async def check_setup(session: FromDishka[AsyncSession]) -> bool:
    """Check if initial setup needed.

    True if setup already complete, False if setup is needed.
    """
    query = select(exists(Directory).where(Directory.parent_id.is_(None)))
    retval = await session.scalars(query)
    return retval.one()


@auth_router.post(
    "/setup",
    status_code=status.HTTP_200_OK,
    responses={423: {"detail": "Locked"}},
)
@inject
async def first_setup(
    request: SetupRequest,
    session: FromDishka[AsyncSession],
    kadmin: FromDishka[AbstractKadmin],
) -> None:
    """Perform initial setup."""
    setup_already_performed = await session.scalar(
        select(Directory).filter(Directory.parent_id.is_(None)),
    )

    if setup_already_performed:
        raise HTTPException(status.HTTP_423_LOCKED)

    data = [  # noqa
        {
            "name": "groups",
            "object_class": "container",
            "attributes": {
                "objectClass": ["top"],
                "sAMAccountName": ["groups"],
            },
            "children": [
                {
                    "name": "domain admins",
                    "object_class": "group",
                    "attributes": {
                        "objectClass": ["top", "posixGroup"],
                        "groupType": ["-2147483646"],
                        "instanceType": ["4"],
                        "sAMAccountName": ["domain admins"],
                        "sAMAccountType": ["268435456"],
                        "gidNumber": ["512"],
                    },
                    "objectSid": 512,
                },
                {
                    "name": "domain users",
                    "object_class": "group",
                    "attributes": {
                        "objectClass": ["top", "posixGroup"],
                        "groupType": ["-2147483646"],
                        "instanceType": ["4"],
                        "sAMAccountName": ["domain users"],
                        "sAMAccountType": ["268435456"],
                        "gidNumber": ["513"],
                    },
                    "objectSid": 513,
                },
                {
                    "name": "readonly domain controllers",
                    "object_class": "group",
                    "attributes": {
                        "objectClass": ["top", "posixGroup"],
                        "groupType": ["-2147483646"],
                        "instanceType": ["4"],
                        "sAMAccountName": ["readonly domain controllers"],
                        "sAMAccountType": ["268435456"],
                        "gidNumber": ["521"],
                    },
                    "objectSid": 521,
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
                        "groups": ["domain admins"],
                    },
                    "attributes": {
                        "objectClass": [
                            "top",
                            "person",
                            "organizationalPerson",
                            "posixAccount",
                            "shadowAccount",
                        ],
                        "pwdLastSet": [ft_now()],
                        "loginShell": ["/bin/bash"],
                        "uidNumber": ["1000"],
                        "gidNumber": ["513"],
                        "userAccountControl": ["512"],
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
                request.password, None,
            )

            if errors:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=errors,
                )

            await default_pwd_policy.create_policy_settings(session, kadmin)

            domain = (await session.scalars(
                select(Directory).filter(Directory.parent_id.is_(None)),
            )).one()

            await create_access_policy(
                name="Root Access Policy",
                can_add=True,
                can_modify=True,
                can_read=True,
                can_delete=True,
                grant_dn=domain.path_dn,
                groups=["cn=domain admins,cn=groups," + domain.path_dn],
                session=session,
            )

            await create_access_policy(
                name="ReadOnly Access Policy",
                can_add=False,
                can_modify=False,
                can_read=True,
                can_delete=False,
                grant_dn=domain.path_dn,
                groups=[
                    "cn=readonly domain controllers,cn=groups," +
                    domain.path_dn,
                ],
                session=session,
            )

            await session.commit()

        except IntegrityError:
            await session.rollback()
            raise HTTPException(status.HTTP_423_LOCKED)
        else:
            get_base_directories.cache_clear()
