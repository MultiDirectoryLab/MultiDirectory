"""IdentityManager: Class for encapsulating authentication business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import URL

from abstract_dao import AbstractService
from config import Settings
from constants import ENTITY_TYPE_DATAS
from enums import MFAFlags
from extra.setup_dev import setup_enviroment
from ldap_protocol.identity.exceptions.auth import (
    AlreadyConfiguredError,
    ForbiddenError,
    LoginFailedError,
    PasswordPolicyError,
    UnauthorizedError,
    UserNotFoundError,
)
from ldap_protocol.identity.mfa_manager import MFAManager
from ldap_protocol.identity.schemas import (
    MFAChallengeResponse,
    OAuth2Form,
    SetupRequest,
)
from ldap_protocol.identity.utils import authenticate_user
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.multifactor import MultifactorAPI
from ldap_protocol.policies.audit.audit_use_case import AuditUseCase
from ldap_protocol.policies.audit.monitor import AuditMonitorUseCase
from ldap_protocol.policies.network_policy import (
    check_mfa_group,
    get_user_network_policy,
)
from ldap_protocol.policies.password import PasswordPolicyUseCases
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.session_storage.repository import SessionRepository
from ldap_protocol.user_account_control import (
    UserAccountControlFlag,
    get_check_uac,
)
from ldap_protocol.utils.helpers import ft_now
from ldap_protocol.utils.queries import get_user
from models import Directory, Group, User
from password_manager import PasswordValidator


class IdentityManager(AbstractService):
    """Authentication manager."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        mfa_api: MultifactorAPI,
        storage: SessionStorage,
        entity_type_dao: EntityTypeDAO,
        password_use_cases: PasswordPolicyUseCases,
        password_validator: PasswordValidator,
        role_use_case: RoleUseCase,
        repository: SessionRepository,
        audit_use_case: AuditUseCase,
        monitor: AuditMonitorUseCase,
        kadmin: AbstractKadmin,
        mfa_manager: MFAManager,
    ) -> None:
        """Initialize dependencies of the manager (via DI).

        :param session: SQLAlchemy AsyncSession
        :param settings: Settings
        :param mfa_api: MultifactorAPI
        :param storage: SessionStorage.
        :param entity_type_dao: EntityTypeDAO
        :param role_use_case: RoleUseCase
        """
        self._session = session
        self._settings = settings
        self._mfa_api = mfa_api
        self._storage = storage
        self._entity_type_dao = entity_type_dao
        self._role_use_case = role_use_case
        self.key_ttl = self._storage.key_ttl
        self._repository = repository
        self._audit_use_case = audit_use_case
        self._monitor = monitor
        self._password_use_cases = password_use_cases
        self._password_validator = password_validator
        self._kadmin = kadmin
        self._mfa_manager = mfa_manager

    def __getattribute__(self, name: str) -> object:
        """Intercept attribute access."""
        attr = super().__getattribute__(name)
        if not callable(attr):
            return attr

        if name == "login":
            return self._monitor.wrap_login(attr)
        elif name == "reset_password":
            return self._monitor.wrap_reset_password(attr)
        elif name == "change_password":
            return self._monitor.wrap_change_password(attr)
        return attr

    async def login(
        self,
        form: OAuth2Form,
        url: URL,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> tuple[MFAChallengeResponse | None, str | None]:
        """Log in a user.

        :param form: OAuth2Form with username and password
        :param url: URL for the MFA callback
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
            self._password_validator,
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
                return await self._mfa_manager.two_factor_protocol(
                    user=user,
                    network_policy=network_policy,
                    url=url,
                    ip=ip,
                    user_agent=user_agent,
                )

        return (
            None,
            await self._repository.create_session_key(
                user,
                ip,
                user_agent,
                self.key_ttl,
            ),
        )

    async def _update_password(
        self,
        identity: str,
        new_password: str,
    ) -> None:
        """Change the user's password and update Kerberos.

        :param identity: str
        :param new_password: str
        :raises UserNotFoundError: if user not found
        :raises PasswordPolicyError: if password does not meet policy
        :raises KRBAPIError: if Kerberos password update failed
        :return: None.
        """
        user = await get_user(self._session, identity)

        if not user:
            raise UserNotFoundError(
                f"User {identity} not found in the database.",
            )

        errors = await self._password_use_cases.check_password_violations(
            new_password,
            user,
        )

        if errors:
            raise PasswordPolicyError(errors)

        try:
            await self._kadmin.create_or_update_principal_pw(
                user.get_upn_prefix(),
                new_password,
            )
        except KRBAPIError:
            raise KRBAPIError(
                "Failed kerberos password update",
            )

        user.password = self._password_validator.get_password_hash(
            new_password,
        )
        await self._password_use_cases.post_save_password_actions(user)
        await self._session.commit()

    async def change_password(self, principal: str, new_password: str) -> None:
        """Synchronize the password for the shadow account."""
        await self._update_password(principal, new_password)

    async def reset_password(
        self,
        identity: str,
        new_password: str,
    ) -> None:
        """Change the user's password and update Kerberos."""
        await self._update_password(identity, new_password)

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
            .filter(Directory.parent_id.is_(None)),
        )  # fmt: skip
        if setup_already_performed:
            raise AlreadyConfiguredError("Setup already performed")

        for entity_type_data in ENTITY_TYPE_DATAS:
            await self._entity_type_dao.create_one(
                name=entity_type_data["name"],  # type: ignore
                object_class_names=entity_type_data["object_class_names"],
                is_system=True,
            )
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
                "name": "Computers",
                "object_class": "organizationalUnit",
                "attributes": {"objectClass": ["top", "container"]},
                "children": [],
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
                            "sam_account_name": request.username,
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
                    password_validator=self._password_validator,
                )
                await self._session.flush()
                errors = await (
                    self
                    ._password_use_cases
                    .check_default_policy_password_violations(
                        password=request.password,
                    )
                )  # fmt: skip
                if errors:
                    raise ForbiddenError(errors)

                await self._password_use_cases.create_policy()
                await self._role_use_case.create_domain_admins_role()
                await self._role_use_case.create_read_only_role()
                await self._audit_use_case.create_policies()
                await self._session.commit()
            except IntegrityError:
                await self._session.rollback()
                raise AlreadyConfiguredError(
                    "Setup already performed (locked)",
                )
