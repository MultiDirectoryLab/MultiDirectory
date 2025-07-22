"""IdentityManager: Class for encapsulating authentication business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.schema import OAuth2Form, SetupRequest
from api.exceptions.auth import (
    AlreadyConfiguredError,
    ForbiddenError,
    LoginFailedError,
    PasswordPolicyError,
    UnauthorizedError,
    UserNotFoundError,
)
from api.exceptions.mfa import MFARequiredError
from config import Settings
from extra.setup_dev import setup_enviroment
from ldap_protocol.identity.session_mixin import SessionKeyCreatorMixin
from ldap_protocol.identity.utils import authenticate_user
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


class IdentityManager(SessionKeyCreatorMixin):
    """Authentication manager."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        mfa_api: MultifactorAPI,
        storage: SessionStorage,
    ) -> None:
        """Initialize dependencies of the manager (via DI).

        :param session: SQLAlchemy AsyncSession
        :param settings: Settings
        :param mfa_api: MultifactorAPI
        :param storage: SessionStorage.
        """
        self._session = session
        self._settings = settings
        self._mfa_api = mfa_api
        self._storage = storage
        self.key_ttl = self._storage.key_ttl

    async def login(
        self,
        form: OAuth2Form,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> str:
        """Log in a user.

        :param form: OAuth2Form with username and password
        :param ip: Client IP
        :param user_agent: Client User-Agent
        :raises UnauthorizedError: if incorrect username or password
        :raises LoginFailedError:
            if user not in group, disabled, expired, or failed policy
        :raises MFARequiredError: if MFA is required
        :return: session key (str)
        """
        user = await authenticate_user(
            self._session,
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
            .limit(1)
            .exists()
        )
        is_part_of_admin_group = (
            await self._session.scalars(select(query))
        ).one()

        if not is_part_of_admin_group:
            raise LoginFailedError("User not part of domain admins")

        uac_check = await get_check_uac(self._session, user.directory_id)

        if uac_check(UserAccountControlFlag.ACCOUNTDISABLE):
            raise LoginFailedError("User account is disabled")

        if user.is_expired():
            raise LoginFailedError("User account is expired")

        network_policy = await get_user_network_policy(
            ip,
            user,
            self._session,
        )
        if network_policy is None:
            raise LoginFailedError("User not part of network policy")

        if self._mfa_api.is_initialized and network_policy.mfa_status in (
            MFAFlags.ENABLED,
            MFAFlags.WHITELIST,
        ):
            request_2fa = True
            if network_policy.mfa_status == MFAFlags.WHITELIST:
                request_2fa = await check_mfa_group(
                    network_policy,
                    user,
                    self._session,
                )
            if request_2fa:
                raise MFARequiredError("Requires MFA connect")

        return await self.create_session_key(
            user,
            self._storage,
            self._settings,
            ip,
            user_agent,
            self._session,
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
        :raises UserNotFoundError: if user not found
        :raises PasswordPolicyError: if password does not meet policy
        :raises KRBAPIError: if Kerberos password update failed
        :return: None.
        """
        user = await get_user(self._session, identity)

        if not user:
            raise UserNotFoundError("User not found")

        policy = await PasswordPolicySchema.get_policy_settings(self._session)
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

        await post_save_password_actions(user, self._session)
        await self._session.commit()

    async def check_setup_needed(self) -> bool:
        """Check if initial setup is needed.

        :return: bool (True if setup is required, False otherwise)
        """
        query = select(exists(Directory).where(Directory.parent_id.is_(None)))
        retval = await self._session.scalars(query)
        return retval.one()

    async def perform_first_setup(self, request: SetupRequest) -> None:
        """Perform the initial setup of structure and policies.

        :param request: SetupRequest with setup parameters
        :raises AlreadyConfiguredError: if setup already performed
        :raises ForbiddenError: if password policy not passed
        :return: None.
        """
        setup_already_performed = await self._session.scalar(
            select(Directory)
            .filter(Directory.parent_id.is_(None))
        )  # fmt: skip
        if setup_already_performed:
            raise AlreadyConfiguredError("Setup already performed")
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
        async with self._session.begin_nested():
            try:
                await setup_enviroment(
                    self._session,
                    dn=request.domain,
                    data=data,
                )
                await self._session.flush()
                default_pwd_policy = PasswordPolicySchema()
                errors = (
                    await default_pwd_policy.validate_password_with_policy(
                        password=request.password,
                        user=None,
                    )
                )
                if errors:
                    raise ForbiddenError(errors)

                await default_pwd_policy.create_policy_settings(self._session)
                domain_query = select(Directory).filter(
                    Directory.parent_id.is_(None)
                )
                domain = (await self._session.scalars(domain_query)).one()

                await create_access_policy(
                    name="Root Access Policy",
                    can_add=True,
                    can_modify=True,
                    can_read=True,
                    can_delete=True,
                    grant_dn=domain.path_dn,
                    groups=["cn=domain admins,cn=groups," + domain.path_dn],
                    session=self._session,
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
                    session=self._session,
                )
                await self._session.commit()
            except IntegrityError:
                await self._session.rollback()
                raise AlreadyConfiguredError(
                    "Setup already performed (locked)"
                )
            else:
                get_base_directories.cache_clear()
