"""MFAManager: Class for encapsulating MFA business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import operator
import traceback
from dataclasses import dataclass
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
    ForbiddenError,
    InvalidCredentialsError,
    MFAError,
    MFATokenError,
    MissingMFACredentialsError,
    NetworkPolicyError,
)
from config import Settings
from ldap_protocol.identity.session_mixin import SessionKeyCreatorMixin
from ldap_protocol.identity.utils import authenticate_user
from ldap_protocol.multifactor import (
    Creds,
    MFA_HTTP_Creds,
    MFA_LDAP_Creds,
    MultifactorAPI,
)
from ldap_protocol.policies.network_policy import get_user_network_policy
from ldap_protocol.session_storage import SessionStorage
from models import CatalogueSetting, User


@dataclass
class UserMFADTO:
    """Data Transfer Object for User MFA credentials."""

    key: str
    username: str


class MFAManager(SessionKeyCreatorMixin):
    """MFA manager."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        storage: SessionStorage,
        mfa_api: MultifactorAPI,
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
        self.key_ttl = self._storage.key_ttl

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
    ) -> UserMFADTO:
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
            raise MFATokenError()

        user_id: int = int(payload.get("uid"))
        user = await self._session.get(User, user_id)
        if user_id is None or not user:
            raise MFATokenError()

        key = await self.create_session_key(
            user,
            self._storage,
            self._settings,
            ip,
            user_agent,
            self._session,
        )

        return UserMFADTO(
            key=key,
            username=user.user_principal_name,
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
        :param user_agent: str
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

        try:
            if self._settings.USE_CORE_TLS:
                url = url.replace(scheme="https")
            redirect_url = await self._mfa_api.get_create_mfa(
                user.user_principal_name,
                url.components.geturl(),
                user.id,
            )

        except self._mfa_api.MFAConnectError:
            if network_policy.bypass_no_connection:
                return (
                    MFAChallengeResponse(status="bypass", message=""),
                    None,
                )
            logger.critical(f"API error {traceback.format_exc()}")
            raise MFAError("Multifactor error")

        except self._mfa_api.MFAMissconfiguredError:
            return (
                MFAChallengeResponse(status="bypass", message=""),
                None,
            )

        except self._mfa_api.MultifactorError as error:
            if network_policy.bypass_service_failure:
                return (
                    MFAChallengeResponse(status="bypass", message=""),
                    None,
                )
            logger.critical(f"API error {traceback.format_exc()}")
            raise MFAError(str(error))

        key = await self.create_session_key(
            user,
            self._storage,
            self._settings,
            ip,
            user_agent,
            self._session,
        )
        return (
            MFAChallengeResponse(
                status="pending",
                message=redirect_url,
            ),
            key,
        )
