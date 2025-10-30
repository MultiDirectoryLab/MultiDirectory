"""IdentityManager: Class for encapsulating authentication business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import URL

from abstract_dao import AbstractService
from config import Settings
from entities import Directory, Group, User
from enums import ErrorCode, MFAFlags
from errors.contracts import ErrorCodeCarrierError
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.identity.dto import SetupDTO
from ldap_protocol.identity.exceptions.auth import (
    AuthValidationError,
    LoginFailedError,
    PasswordPolicyError,
    UnauthorizedError,
    UserNotFoundError,
)
from ldap_protocol.identity.identity_provider import IdentityProvider
from ldap_protocol.identity.mfa_manager import MFAManager
from ldap_protocol.identity.schemas import LoginDTO, OAuth2Form
from ldap_protocol.identity.use_cases import SetupUseCase
from ldap_protocol.identity.utils import authenticate_user
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.multifactor import MultifactorAPI
from ldap_protocol.objects import UserAccountControlFlag
from ldap_protocol.policies.audit.monitor import AuditMonitorUseCase
from ldap_protocol.policies.network_policy import (
    check_mfa_group,
    get_user_network_policy,
)
from ldap_protocol.policies.password import PasswordPolicyUseCases
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.session_storage.repository import SessionRepository
from ldap_protocol.user_account_control import get_check_uac
from ldap_protocol.utils.queries import get_user
from password_manager import PasswordValidator
from repo.pg.tables import queryable_attr as qa


class IdentityManager(AbstractService):
    """Authentication manager."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        mfa_api: MultifactorAPI,
        storage: SessionStorage,
        password_use_cases: PasswordPolicyUseCases,
        password_validator: PasswordValidator,
        repository: SessionRepository,
        monitor: AuditMonitorUseCase,
        kadmin: AbstractKadmin,
        mfa_manager: MFAManager,
        setup_use_case: SetupUseCase,
        identity_provider: IdentityProvider,
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
        self.key_ttl = self._storage.key_ttl
        self._repository = repository
        self._monitor = monitor
        self._password_use_cases = password_use_cases
        self._password_validator = password_validator
        self._kadmin = kadmin
        self._mfa_manager = mfa_manager
        self._setup_use_case = setup_use_case
        self._identity_provider = identity_provider

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
    ) -> LoginDTO:
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
            raise ErrorCodeCarrierError(
                UnauthorizedError("Incorrect username or password"),
                ErrorCode.INVALID_CREDENTIALS,
            )

        query = (
            select(Group)
            .join(qa(Group.users))
            .join(qa(Group.directory))
            .filter(
                qa(User.id) == user.id,
                qa(Directory.name) == "domain admins",
            )
            .limit(1)
            .exists()
        )
        is_part_of_admin_group = (
            await self._session.scalars(select(query))
        ).one()

        if not is_part_of_admin_group:
            raise ErrorCodeCarrierError(
                LoginFailedError("User not part of domain admins"),
                ErrorCode.PERMISSION_DENIED,
            )

        uac_check = await get_check_uac(self._session, user.directory_id)

        if uac_check(UserAccountControlFlag.ACCOUNTDISABLE):
            raise ErrorCodeCarrierError(
                LoginFailedError("User account is disabled"),
                ErrorCode.PERMISSION_DENIED,
            )

        if user.is_expired():
            raise ErrorCodeCarrierError(
                LoginFailedError("User account is expired"),
                ErrorCode.PERMISSION_DENIED,
            )

        network_policy = await get_user_network_policy(
            ip,
            user,
            self._session,
            policy_type="is_http",
        )
        if network_policy is None:
            raise ErrorCodeCarrierError(
                LoginFailedError("User not part of network policy"),
                ErrorCode.PERMISSION_DENIED,
            )

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
                (
                    mfa_challenge,
                    key,
                ) = await self._mfa_manager.two_factor_protocol(
                    user=user,
                    network_policy=network_policy,
                    url=url,
                    ip=ip,
                    user_agent=user_agent,
                )
                return LoginDTO(key, mfa_challenge)

        session_key = await self._repository.create_session_key(
            user,
            ip,
            user_agent,
            self.key_ttl,
        )
        return LoginDTO(session_key, None)

    async def _update_password(
        self,
        identity: str | User,
        new_password: str,
        include_krb: bool,
    ) -> None:
        """Change the user's password and update Kerberos.

        :param identity: str
        :param new_password: str
        :param include_krb: bool
        :raises UserNotFoundError: if user not found
        :raises PasswordPolicyError: if password does not meet policy
        :raises KRBAPIChangePasswordError: if Kerberos password update failed
        :return: None.
        """
        user = (
            await get_user(self._session, identity)
            if isinstance(identity, str)
            else identity
        )

        if not user:
            raise ErrorCodeCarrierError(
                UserNotFoundError(
                    f"User {identity} not found in the database.",
                ),
                ErrorCode.ENTITY_NOT_FOUND,
            )

        if await self._password_use_cases.is_password_change_restricted(
            user.directory_id,
        ):
            raise ErrorCodeCarrierError(
                PermissionError(
                    f"User {identity} is not allowed to change the password.",
                ),
                ErrorCode.PERMISSION_DENIED,
            )

        errors = await self._password_use_cases.check_password_violations(
            new_password,
            user,
        )

        if errors:
            raise ErrorCodeCarrierError(
                PasswordPolicyError(errors),
                ErrorCode.PASSWORD_POLICY_VIOLATION,
            )

        if include_krb:
            await self._kadmin.create_or_update_principal_pw(
                user.get_upn_prefix(),
                new_password,
            )

        user.password = self._password_validator.get_password_hash(
            new_password,
        )
        await self._password_use_cases.post_save_password_actions(user)
        await self._session.commit()

        await self._repository.clear_user_sessions(identity)

    async def sync_password_from_service(
        self,
        principal: str,
        new_password: str,
    ) -> None:
        """Synchronize the password from the shadow api."""
        await self._update_password(
            principal,
            new_password,
            include_krb=False,
        )

    async def reset_password(
        self,
        identity: str,
        new_password: str,
        old_password: str | None,
    ) -> None:
        """Change the user's password and update Kerberos."""
        raise_not_verified = False

        current_user_schema = await self.get_current_user()
        resolved_identity = await get_user(
            self._session,
            identity,
        )

        if resolved_identity is None:
            raise UserNotFoundError(
                f"User {identity} not found in the database.",
            )

        if current_user_schema.id == resolved_identity.id:
            if old_password is None:
                raise AuthValidationError(
                    "Old password must be provided "
                    "when changing your own password.",
                )

            if resolved_identity.password is None:
                raise AuthValidationError(
                    "Cannot change password for user without a set password.",
                )

            raise_not_verified = (
                self._password_validator.verify_password(
                    old_password,
                    resolved_identity.password,
                )
                is False
            )

        if raise_not_verified:
            raise UnauthorizedError("Old password is incorrect.")

        await self._update_password(
            identity,
            new_password,
            include_krb=True,
        )

    async def check_setup_needed(self) -> bool:
        """Check if initial setup is needed.

        :return: bool (True if setup is required, False otherwise)
        """
        return await self._setup_use_case.is_setup()

    async def perform_first_setup(self, dto: SetupDTO) -> None:
        """Perform the initial setup of structure and policies.

        :param dto: SetupDTO with setup parameters
        :raises AlreadyConfiguredError: if setup already performed
        :raises ForbiddenError: if password policy not passed
        :return: None.
        """
        await self._setup_use_case.setup(dto)

    async def get_current_user(self) -> UserSchema:
        """Load the authenticated user using request-bound session data."""
        return await self._identity_provider.get_current_user()

    def set_new_session_key(self, key: str) -> None:
        """Set a new session key.

        Args:
            key: New session key to set.

        """
        self._identity_provider.set_new_session_key(key)
