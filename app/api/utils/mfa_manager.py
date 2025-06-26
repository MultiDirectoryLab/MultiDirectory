"""MFAManager: Class for encapsulating MFA business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import operator
import traceback
from ipaddress import IPv4Address, IPv6Address

from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from jose import jwt
from jose.exceptions import JWKError, JWTError
from loguru import logger
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.oauth2 import ALGORITHM, authenticate_user
from api.auth.schema import (
    MFAChallengeResponse,
    MFACreateRequest,
    MFAGetResponse,
    OAuth2Form,
)
from api.auth.utils import create_and_set_session_key
from api.utils.exceptions import ForbiddenError, MFAError, NotFoundError
from config import Settings
from ldap_protocol.multifactor import (
    Creds,
    MFA_HTTP_Creds,
    MFA_LDAP_Creds,
    MultifactorAPI,
)
from ldap_protocol.policies.network_policy import get_user_network_policy
from ldap_protocol.session_storage import SessionStorage
from models import CatalogueSetting, User as DBUser


class MFAManager:
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
        self.__session = session
        self.__settings = settings
        self.__storage = storage
        self.__mfa_api = mfa_api

    async def setup_mfa(self, mfa: MFACreateRequest) -> bool:
        """Create or update MFA keys.

        :param mfa: MFACreateRequest
        :return: bool
        """
        async with self.__session.begin_nested():
            await self.__session.execute(
                delete(CatalogueSetting).filter(
                    operator.or_(
                        CatalogueSetting.name == mfa.key_name,
                        CatalogueSetting.name == mfa.secret_name,
                    ),
                )
            )
            await self.__session.flush()
            self.__session.add_all(
                (
                    CatalogueSetting(name=mfa.key_name, value=mfa.mfa_key),
                    CatalogueSetting(
                        name=mfa.secret_name, value=mfa.mfa_secret
                    ),
                )
            )
            await self.__session.commit()
        return True

    async def remove_mfa(self, scope: str) -> None:
        """Delete MFA keys by scope.

        :param scope: str
        :return: None
        """
        if scope == "http":
            keys = ["mfa_key", "mfa_secret"]
        else:
            keys = ["mfa_key_ldap", "mfa_secret_ldap"]
        await self.__session.execute(
            delete(CatalogueSetting)
            .filter(CatalogueSetting.name.in_(keys))
        )  # fmt: skip

        await self.__session.commit()

    async def get_mfa(
        self,
        mfa_creds: MFA_HTTP_Creds | None,
        mfa_creds_ldap: MFA_LDAP_Creds | None,
    ) -> MFAGetResponse:
        """Get MFA keys for http and ldap.

        :param mfa_creds: MFA_HTTP_Creds
        :param mfa_creds_ldap: MFA_LDAP_Creds
        :return: MFAGetResponse.
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
    ) -> RedirectResponse:
        """Process MFA callback and return redirect.

        :param access_token: str
        :param mfa_creds: MFA_HTTP_Creds
        :param ip: str
        :param user_agent: str
        :return: RedirectResponse.
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
            raise ForbiddenError("Invalid MFA token")

        user_id: int = int(payload.get("uid"))
        user = await self.__session.get(DBUser, user_id)
        if user is None:
            raise NotFoundError("User not found")
        response = RedirectResponse("/", 302)

        await create_and_set_session_key(
            user,
            self.__session,
            self.__settings,
            response,
            self.__storage,
            ip,
            user_agent,
        )
        return response

    async def two_factor_protocol(
        self,
        form: OAuth2Form,
        request: Request,
        response: Response,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> MFAChallengeResponse:
        """Initiate two-factor protocol with application.

        :param form: OAuth2Form
        :param request: FastAPI Request
        :param response: FastAPI Response
        :param ip: str
        :param user_agent: str
        :return: MFAChallengeResponse.
        :raises ForbiddenError: if credentials invalid or policy not passed
        :raises MFAError: for MFA-specific errors
        """
        if not self.__mfa_api:
            raise ForbiddenError("Missing API credentials")
        user = await authenticate_user(
            self.__session, form.username, form.password
        )
        if not user:
            raise ForbiddenError("Invalid credentials")
        network_policy = await get_user_network_policy(
            ip, user, self.__session
        )
        if network_policy is None:
            raise ForbiddenError("Network policy not passed")
        try:
            url = request.url_for("callback_mfa")
            if self.__settings.USE_CORE_TLS:
                url = url.replace(scheme="https")
            redirect_url = await self.__mfa_api.get_create_mfa(
                user.user_principal_name,
                url.components.geturl(),
                user.id,
            )
        except self.__mfa_api.MFAConnectError:
            if network_policy.bypass_no_connection:
                await create_and_set_session_key(
                    user,
                    self.__session,
                    self.__settings,
                    response,
                    self.__storage,
                    ip,
                    user_agent,
                )
                return MFAChallengeResponse(status="bypass", message="")

            logger.critical(f"API error {traceback.format_exc()}")
            raise MFAError("Multifactor error")
        except self.__mfa_api.MFAMissconfiguredError:
            await create_and_set_session_key(
                user,
                self.__session,
                self.__settings,
                response,
                self.__storage,
                ip,
                user_agent,
            )
            return MFAChallengeResponse(status="bypass", message="")
        except self.__mfa_api.MultifactorError as error:
            if network_policy.bypass_service_failure:
                await create_and_set_session_key(
                    user,
                    self.__session,
                    self.__settings,
                    response,
                    self.__storage,
                    ip,
                    user_agent,
                )
                return MFAChallengeResponse(status="bypass", message="")

            logger.critical(f"API error {traceback.format_exc()}")
            raise MFAError(str(error))
        return MFAChallengeResponse(status="pending", message=redirect_url)
