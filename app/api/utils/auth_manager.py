"""AuthManager: Class for encapsulating authentication business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from fastapi import Response
from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.oauth2 import authenticate_user
from api.auth.schema import OAuth2Form, SetupRequest
from api.auth.utils import create_and_set_session_key
from api.utils.exceptions import (
    ForbiddenError,
    MFAError,
    PasswordPolicyError,
    UnauthorizedError,
    UserNotFoundError,
)
from config import Settings
from extra.setup_dev import setup_enviroment
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
from ldap_protocol.utils.queries import get_base_directories, get_user
from models import Directory, Group, MFAFlags, User
from security import get_password_hash


class AuthManager:
    """Authentication manager."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        mfa_api: MultifactorAPI | None,
        storage: SessionStorage,
    ) -> None:
        """Initialize dependencies of the manager (via DI).

        :param session: SQLAlchemy AsyncSession
        :param settings: Settings
        :param mfa_api: MultifactorAPI
        :param storage: SessionStorage.
        """
        self.__session = session
        self.__settings = settings
        self.__mfa_api = mfa_api
        self.__storage = storage

    async def login(
        self,
        form: OAuth2Form,
        response: Response,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> None:
        """Log in a user.

        :param form: OAuth2Form with username and password
        :param response: FastAPI response
        :param ip: Client IP
        :param user_agent: Client User-Agent
        :raises AuthManager.UnauthorizedError: if incorrect username/password
        :raises AuthManager.ForbiddenError:
            if user not in group, disabled, expired, or failed policy
        :raises AuthManager.MFARequiredError: if MFA is required
        :return: None
        """
        user = await authenticate_user(
            self.__session,
            form.username,
            form.password,
        )
        if not user:
            raise UnauthorizedError("Incorrect username or password")

        query = (
            select(Group)
            .join(Group.users)
            .join(Group.directory)
            .filter(User.id == user.id, Directory.name == "domain admins")
            .exists()
        )
        is_part_of_admin_group = (
            await self.__session.scalars(select(query))
        ).one()
        if not is_part_of_admin_group:
            raise ForbiddenError("User not part of domain admins")

        uac_check = await get_check_uac(self.__session, user.directory_id)
        if uac_check(UserAccountControlFlag.ACCOUNTDISABLE):
            raise ForbiddenError("User account is disabled")
        if user.is_expired():
            raise ForbiddenError("User account is expired")

        network_policy = await get_user_network_policy(
            ip,
            user,
            self.__session,
        )
        if network_policy is None:
            raise ForbiddenError("User not part of network policy")

        if self.__mfa_api and network_policy.mfa_status in (
            MFAFlags.ENABLED,
            MFAFlags.WHITELIST,
        ):
            request_2fa = True
            if network_policy.mfa_status == MFAFlags.WHITELIST:
                request_2fa = await check_mfa_group(
                    network_policy, user, self.__session
                )
            if request_2fa:
                raise MFAError("Requires MFA connect")

        await create_and_set_session_key(
            user,
            self.__session,
            self.__settings,
            response,
            self.__storage,
            ip,
            user_agent,
        )

    async def reset_password(
        self,
        identity: str,
        new_password: str,
        kadmin: AbstractKadmin,
    ) -> None:
        """Change the user's password and update Kerberos.

        :param identity: str
        :param new_password: str
        :param kadmin: Kerberos kadmin client
        :raises AuthManager.ForbiddenError:
            if user not found, policy not passed, or Kerberos error
        :return: None.
        """
        user = await get_user(self.__session, identity)

        if not user:
            raise UserNotFoundError("User not found")

        policy = await PasswordPolicySchema.get_policy_settings(self.__session)
        errors = await policy.validate_password_with_policy(new_password, user)

        if errors:
            raise PasswordPolicyError(errors)

        user.password = get_password_hash(new_password)

        try:
            await kadmin.create_or_update_principal_pw(
                user.get_upn_prefix(),
                new_password,
            )
        except KRBAPIError:
            raise KRBAPIError(
                "Failed kerberos password update",
            )

        await post_save_password_actions(user, self.__session)
        await self.__session.commit()

    async def check_setup_needed(self) -> bool:
        """Check if initial setup is needed.

        :return: bool.
        """
        query = select(exists(Directory).where(Directory.parent_id.is_(None)))
        retval = await self.__session.scalars(query)
        return retval.one()

    async def perform_first_setup(self, request: SetupRequest) -> None:
        """Perform the initial setup of structure and policies.

        :param request: Any (expected object with setup parameters)
        :raises AuthManager.ForbiddenError: if setup already performed
        :return: None.
        """
        setup_already_performed = await self.__session.scalar(
            select(Directory)
            .filter(Directory.parent_id.is_(None))
        )  # fmt: skip
        if setup_already_performed:
            raise ForbiddenError("Setup already performed")
        data = [
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
                                "inetOrgPerson",
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
        async with self.__session.begin_nested():
            try:
                await setup_enviroment(
                    self.__session,
                    dn=request.domain,
                    data=data,
                )
                await self.__session.flush()
                default_pwd_policy = PasswordPolicySchema()
                errors = (
                    await default_pwd_policy.validate_password_with_policy(
                        password=request.password,
                        user=None,
                    )
                )
                if errors:
                    raise ForbiddenError(errors)
                await default_pwd_policy.create_policy_settings(self.__session)
                domain_query = select(Directory).filter(
                    Directory.parent_id.is_(None)
                )
                domain = (await self.__session.scalars(domain_query)).one()
                await create_access_policy(
                    name="Root Access Policy",
                    can_add=True,
                    can_modify=True,
                    can_read=True,
                    can_delete=True,
                    grant_dn=domain.path_dn,
                    groups=["cn=domain admins,cn=groups," + domain.path_dn],
                    session=self.__session,
                )
                await create_access_policy(
                    name="ReadOnly Access Policy",
                    can_add=False,
                    can_modify=False,
                    can_read=True,
                    can_delete=False,
                    grant_dn=domain.path_dn,
                    groups=[
                        "cn=readonly domain controllers,cn=groups,"
                        + domain.path_dn,
                    ],
                    session=self.__session,
                )
                await self.__session.commit()
            except IntegrityError:
                await self.__session.rollback()
                raise ForbiddenError("Setup already performed (locked)")
            else:
                get_base_directories.cache_clear()
