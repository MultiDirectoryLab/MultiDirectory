"""Auth api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Body, Depends, HTTPException, Response, status
from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from extra.setup_dev import setup_enviroment
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.multifactor import MultifactorAPI
from ldap_protocol.policies.access_policy import create_access_policy
from ldap_protocol.policies.network_policy import (
    check_mfa_group,
    get_user_network_policy,
)
from ldap_protocol.policies.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.user_account_control import (
    UserAccountControlFlag,
    get_check_uac,
)
from ldap_protocol.utils.helpers import ft_now
from ldap_protocol.utils.queries import get_base_directories
from models import Directory, Group, MFAFlags, User
from security import get_password_hash

from .oauth2 import authenticate_user, get_current_user, get_user
from .schema import OAuth2Form, SetupRequest
from .utils import (
    create_and_set_session_key,
    get_ip_from_request,
    get_user_agent_from_request,
)

auth_router = APIRouter(prefix="/auth", tags=["Auth"], route_class=DishkaRoute)


@auth_router.post("/")
async def login(
    form: Annotated[OAuth2Form, Depends()],
    session: FromDishka[AsyncSession],
    settings: FromDishka[Settings],
    mfa: FromDishka[MultifactorAPI],
    storage: FromDishka[SessionStorage],
    response: Response,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
    user_agent: Annotated[str, Depends(get_user_agent_from_request)],
) -> None:
    """Create session to cookies and storage.

    - **username**: username formats:
    `DN`, `userPrincipalName`, `saMAccountName`
    - **password**: password

    \f
    :param Annotated[OAuth2Form, Depends form: login form
    :param FromDishka[AsyncSession] session: db
    :param FromDishka[Settings] settings: app settings
    :param FromDishka[MultifactorAPI] mfa: mfa api wrapper
    :param FromDishka[SessionStorage] storage: session storage
    :param Response response: FastAPI response
    :param Annotated[IPv4Address  |  IPv6Address, Depends ip: client ip
    :raises HTTPException: 401 if incorrect username or password
    :raises HTTPException: 403 if user not part of domain admins
    :raises HTTPException: 403 if user account is disabled
    :raises HTTPException: 403 if user account is expired
    :raises HTTPException: 403 if ip is not provided
    :raises HTTPException: 403 if user not part of network policy
    :raises HTTPException: 426 if mfa required
    :return None: None
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

    if not ip:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    network_policy = await get_user_network_policy(ip, user, session)

    if network_policy is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    if mfa and network_policy.mfa_status in (
        MFAFlags.ENABLED, MFAFlags.WHITELIST,
    ):
        request_2fa = True
        if (network_policy.mfa_status == MFAFlags.WHITELIST):
            request_2fa = await check_mfa_group(network_policy, user, session)

        if request_2fa:
            raise HTTPException(
                status.HTTP_426_UPGRADE_REQUIRED,
                detail="Requires MFA connect",
            )

    await create_and_set_session_key(
        user, session, settings,
        response, storage, ip, user_agent,
    )


@auth_router.get("/me")
async def users_me(
    user: Annotated[UserSchema, Depends(get_current_user)],
) -> UserSchema:
    """Get current logged in user data."""
    return user


@auth_router.delete("/", response_class=Response)
async def logout(
    response: Response,
    storage: FromDishka[SessionStorage],
    user: Annotated[UserSchema, Depends(get_current_user)],
) -> None:
    """Delete token cookies."""
    response.delete_cookie("id", httponly=True)
    await storage.delete_user_session(user.session_id)


@auth_router.patch(
    "/user/password",
    status_code=200,
    dependencies=[Depends(get_current_user)],
)
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
    :param FromDishka[AsyncSession] session: db
    :param FromDishka[AbstractKadmin] kadmin: kadmin api
    :param Annotated[str, Body identity: reset target user
    :param Annotated[str, Body new_password: new password for user
    :raises HTTPException: 404 if user not found
    :raises HTTPException: 422 if password not valid
    :raises HTTPException: 424 if kerberos password update failed
    :return None: None
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
