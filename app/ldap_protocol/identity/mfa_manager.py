"""MFAManager: Class for encapsulating MFA business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import operator
import traceback
import weakref
from ipaddress import IPv4Address, IPv6Address

from jose import jwt
from jose.exceptions import JWKError, JWTError
from loguru import logger
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import URL

from api.auth.oauth2 import ALGORITHM
from api.auth.schema import (
    MFAChallengeResponse,
    MFACreateRequest,
    MFAGetResponse,
    OAuth2Form,
)
from api.exceptions.mfa import (
    AuthenticationError,
    ForbiddenError,
    InvalidCredentialsError,
    MFAError,
    MFATokenError,
    MissingMFACredentialsError,
    NetworkPolicyError,
)
from config import Settings
from enums import MFAChallengeStatuses, MFAFlags
from ldap_protocol.identity.utils import authenticate_user, get_user
from ldap_protocol.multifactor import (
    Creds,
    LDAPMultiFactorAPI,
    MFA_HTTP_Creds,
    MFA_LDAP_Creds,
    MultifactorAPI,
)
from ldap_protocol.policies.audit.monitor import AuditMonitorUseCase
from ldap_protocol.policies.network_policy import (
    check_mfa_group,
    get_user_network_policy,
)
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.session_storage.repository import SessionRepository
from models import CatalogueSetting, User


class MFAManager:
    """MFA manager."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        storage: SessionStorage,
        mfa_api: MultifactorAPI,
        ldap_mfa_api: LDAPMultiFactorAPI,
        repository: SessionRepository,
        monitor: AuditMonitorUseCase,
    ) -> None:
        """Initialize dependencies via DI.

        :param session: SQLAlchemy AsyncSession
        :param settings: Settings
        :param storage: SessionStorage
        :param mfa_api: MultifactorAPI
        """
        self._session = session
        self._settings = settings
        self._storage = storage
        self._mfa_api = mfa_api
        self._ldap_mfa_api = ldap_mfa_api
        self.key_ttl = self._storage.key_ttl
        self._repository = repository
        self._monitor = monitor

    def __getattribute__(self, name: str) -> object:
        """Intercept attribute access."""
        attr = super().__getattribute__(name)
        if not callable(attr):
            return attr

        if name == "callback_mfa":
            return self._monitor.wrap_callback_mfa(attr)
        elif name == "proxy_request":
            return self._monitor.wrap_proxy_request(attr)
        return attr

    async def setup_mfa(self, mfa: MFACreateRequest) -> bool:
        """Create or update MFA keys.

        :param mfa: MFACreateRequest
        :return: bool
        """
        async with self._session.begin_nested():
            await self._session.execute(
                delete(CatalogueSetting).filter(
                    operator.or_(
                        CatalogueSetting.name == mfa.key_name,
                        CatalogueSetting.name == mfa.secret_name,
                    ),
                ),
            )
            await self._session.flush()
            self._session.add_all(
                (
                    CatalogueSetting(name=mfa.key_name, value=mfa.mfa_key),
                    CatalogueSetting(
                        name=mfa.secret_name,
                        value=mfa.mfa_secret,
                    ),
                ),
            )
            await self._session.commit()
        return True

    async def remove_mfa(self, scope: str) -> None:
        """Delete MFA keys by scope.

        :param scope: str ('http' or 'ldap')
        :return: None
        """
        if scope == "http":
            keys = ["mfa_key", "mfa_secret"]
        else:
            keys = ["mfa_key_ldap", "mfa_secret_ldap"]
        await self._session.execute(
            delete(CatalogueSetting)
            .filter(CatalogueSetting.name.in_(keys)),
        )  # fmt: skip

        await self._session.commit()

    async def get_mfa(
        self,
        mfa_creds: MFA_HTTP_Creds | None,
        mfa_creds_ldap: MFA_LDAP_Creds | None,
    ) -> MFAGetResponse:
        """Get MFA keys for http and ldap.

        :param mfa_creds: MFA_HTTP_Creds or None
        :param mfa_creds_ldap: MFA_LDAP_Creds or None
        :return: MFAGetResponse
        """
        if not mfa_creds:
            mfa_creds = MFA_HTTP_Creds(Creds(None, None))

        if not mfa_creds_ldap:
            mfa_creds_ldap = MFA_LDAP_Creds(Creds(None, None))

        return MFAGetResponse(
            mfa_key=mfa_creds.key,
            mfa_secret=mfa_creds.secret,
            mfa_key_ldap=mfa_creds_ldap.key,
            mfa_secret_ldap=mfa_creds_ldap.secret,
        )

    async def callback_mfa(
        self,
        access_token: str,
        mfa_creds: MFA_HTTP_Creds,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> str:
        """Process MFA callback and return session key.

        :param access_token: str
        :param mfa_creds: MFA_HTTP_Creds
        :param ip: IPv4Address | IPv6Address
        :param user_agent: str
        :return: str (session key)
        :raises ForbiddenError: if MFA credentials missing
        :raises MFATokenError: if token is invalid or user not found
        """
        if not mfa_creds or not mfa_creds.secret:
            raise ForbiddenError("MFA credentials missing")
        try:
            payload = jwt.decode(
                access_token,
                mfa_creds.secret,
                audience=mfa_creds.key,
                algorithms=ALGORITHM,
            )
        except (JWTError, AttributeError, JWKError) as err:
            logger.error(f"Invalid MFA token: {err}")
            raise MFATokenError("Invalid MFA token")

        user_id: int = int(payload.get("uid"))
        user = await self._session.get(User, user_id)
        if user_id is None or not user:
            raise MFATokenError("User not found")

        return await self._repository.create_session_key(
            user,
            ip,
            user_agent,
            self.key_ttl,
        )

    async def _create_bypass_data(
        self,
        user: User,
        message: str,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> tuple[MFAChallengeResponse, str | None]:
        """Create session key and response.

        :param user: User
        :param message: str
        :param ip: IPv4Address | IPv6Address
        :param user_agent: str
        :return: tuple[MFAChallengeResponse, str | None]
        """
        key = await self._repository.create_session_key(
            user,
            ip,
            user_agent,
            self.key_ttl,
        )
        return (
            MFAChallengeResponse(
                status=MFAChallengeStatuses.BYPASS,
                message=message,
            ),
            key,
        )

    async def two_factor_protocol(
        self,
        form: OAuth2Form,
        url: URL,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> tuple[MFAChallengeResponse, str | None]:
        """Initiate two-factor protocol with application.

        :param form: OAuth2Form
        :param url: URL for MFA callback
        :param ip: IP address
        :return:
            tuple[MFAChallengeResponse, str | None] (session key | None)
        :raises MissingMFACredentialsError: if MFA is not initialized
        :raises InvalidCredentialsError: if credentials are invalid
        :raises NetworkPolicyError: if network policy is not passed
        :raises MFAError: for MFA-specific errors
        """
        if not self._mfa_api.is_initialized:
            raise MissingMFACredentialsError()
        user = await authenticate_user(
            self._session,
            form.username,
            form.password,
        )
        if not user:
            raise InvalidCredentialsError()

        network_policy = await get_user_network_policy(ip, user, self._session)
        if network_policy is None:
            raise NetworkPolicyError()

        bypass_coro = self._create_bypass_data(
            user,
            "",
            ip,
            user_agent,
        )
        try:
            if self._settings.USE_CORE_TLS:
                url = url.replace(scheme="https")
            redirect_url = await self._mfa_api.get_create_mfa(
                user.user_principal_name,
                url.components.geturl(),
                user.id,
            )
            weakref.finalize(bypass_coro, bypass_coro.close)

        except self._mfa_api.MFAConnectError:
            if network_policy.bypass_no_connection:
                return await bypass_coro
            logger.critical(f"API error {traceback.format_exc()}")
            raise MFAError("Multifactor error")

        except self._mfa_api.MFAMissconfiguredError:
            return await bypass_coro

        except self._mfa_api.MultifactorError as error:
            if network_policy.bypass_service_failure:
                return await bypass_coro
            logger.critical(f"API error {traceback.format_exc()}")
            raise MFAError(str(error))

        return (
            MFAChallengeResponse(
                status=MFAChallengeStatuses.PENDING,
                message=redirect_url,
            ),
            None,
        )

    async def proxy_request(self, principal: str, ip: IPv4Address) -> None:
        """Proxy a request to the shadow account.

        Args:
            principal (str): The user principal name.
            ip (IPv4Address): The IP address of the request.

        Raises:
            UserNotFoundError: If the user is not found in the database.
            NetworkPolicyNotFoundError: If policy is not found for the user.
            AuthenticationError: If the authentication fails.

        """
        user = await get_user(self._session, principal)

        if not user:
            raise InvalidCredentialsError(
                f"User {principal} not found in the database.",
            )

        network_policy = await get_user_network_policy(
            ip,
            user,
            self._session,
        )

        if network_policy is None or not network_policy.is_kerberos:
            raise NetworkPolicyError(
                f"Network policy not found for user {principal}.",
            )

        if (
            not self._ldap_mfa_api
            or network_policy.mfa_status == MFAFlags.DISABLED
        ):
            return
        elif network_policy.mfa_status in (
            MFAFlags.ENABLED,
            MFAFlags.WHITELIST,
        ):
            if (
                network_policy.mfa_status == MFAFlags.WHITELIST
                and not await check_mfa_group(
                    network_policy,
                    user,
                    self._session,
                )
            ):
                return
            try:
                if await self._ldap_mfa_api.ldap_validate_mfa(
                    user.user_principal_name,
                    None,
                ):
                    return

            except MultifactorAPI.MFAConnectError:
                logger.error("MFA connect error")
                if network_policy.bypass_no_connection:
                    return
            except MultifactorAPI.MFAMissconfiguredError:
                logger.error("MFA missconfigured error")
                return
            except MultifactorAPI.MultifactorError:
                logger.error("MFA service failure")
                if network_policy.bypass_service_failure:
                    return

        raise AuthenticationError("Authentication failed.")
