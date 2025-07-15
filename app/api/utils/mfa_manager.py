"""MFAManager: Class for encapsulating MFA business logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import operator
import traceback
from ipaddress import IPv4Address, IPv6Address

from fastapi import HTTPException, Request, Response, status
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
from api.utils.exceptions.mfa import (
    ForbiddenError,
    InvalidCredentialsError,
    MFAError,
    MFATokenError,
    MissingMFACredentialsError,
    NetworkPolicyError,
    NotFoundError,
)
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
        self._session = session
        self._settings = settings
        self._storage = storage
        self._mfa_api = mfa_api

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
                )
            )
            await self._session.flush()
            self._session.add_all(
                (
                    CatalogueSetting(name=mfa.key_name, value=mfa.mfa_key),
                    CatalogueSetting(
                        name=mfa.secret_name,
                        value=mfa.mfa_secret,
                    ),
                )
            )
            await self._session.commit()
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
        await self._session.execute(
            delete(CatalogueSetting)
            .filter(CatalogueSetting.name.in_(keys))
        )  # fmt: skip

        await self._session.commit()

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
            raise MFATokenError()

        user_id: int = int(payload.get("uid"))
        user = await self._session.get(DBUser, user_id)
        if user_id is None or not user:
            raise MFATokenError()

        response = RedirectResponse("/", 302)
        await create_and_set_session_key(
            user,
            self._session,
            self._settings,
            response,
            self._storage,
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
        if not self._mfa_api.is_initialized:
            raise MissingMFACredentialsError()
        user = await authenticate_user(
            self._session, form.username, form.password
        )
        if not user:
            raise InvalidCredentialsError()
        network_policy = await get_user_network_policy(ip, user, self._session)
        if network_policy is None:
            raise NetworkPolicyError()
        try:
            url = request.url_for("callback_mfa")
            if self._settings.USE_CORE_TLS:
                url = url.replace(scheme="https")
            redirect_url = await self._mfa_api.get_create_mfa(
                user.user_principal_name,
                url.components.geturl(),
                user.id,
            )
        except self._mfa_api.MFAConnectError:
            if network_policy.bypass_no_connection:
                await create_and_set_session_key(
                    user,
                    self._session,
                    self._settings,
                    response,
                    self._storage,
                    ip,
                    user_agent,
                )
                return MFAChallengeResponse(status="bypass", message="")
            logger.critical(f"API error {traceback.format_exc()}")
            raise MFAError("Multifactor error")
        except self._mfa_api.MFAMissconfiguredError:
            await create_and_set_session_key(
                user,
                self._session,
                self._settings,
                response,
                self._storage,
                ip,
                user_agent,
            )
            return MFAChallengeResponse(status="bypass", message="")
        except self._mfa_api.MultifactorError as error:
            if network_policy.bypass_service_failure:
                await create_and_set_session_key(
                    user,
                    self._session,
                    self._settings,
                    response,
                    self._storage,
                    ip,
                    user_agent,
                )
                return MFAChallengeResponse(status="bypass", message="")
            logger.critical(f"API error {traceback.format_exc()}")
            raise MFAError(str(error))
        return MFAChallengeResponse(status="pending", message=redirect_url)


class MFAManagerFastAPIAdapter:
    """Adapter for using MFAManager with FastAPI."""

    def __init__(self, mfa_manager: "MFAManager"):
        """Initialize the adapter with a domain MFAManager instance.

        :param mfa_manager: MFAManager instance (domain logic)
        """
        self._manager = mfa_manager

    async def setup_mfa(self, mfa: MFACreateRequest) -> bool:
        """Create or update MFA keys.

        :param mfa: MFACreateRequest
        :return: bool
        """
        return await self._manager.setup_mfa(mfa)

    async def remove_mfa(self, scope: str) -> None:
        """Delete MFA keys by scope.

        :param scope: str
        :return: None
        """
        await self._manager.remove_mfa(scope)

    async def get_mfa(
        self,
        mfa_creds: MFA_HTTP_Creds,
        mfa_creds_ldap: MFA_LDAP_Creds,
    ) -> MFAGetResponse:
        """Get MFA keys for http and ldap.

        :param mfa_creds: MFA_HTTP_Creds
        :param mfa_creds_ldap: MFA_LDAP_Creds
        :return: MFAGetResponse
        """
        return await self._manager.get_mfa(mfa_creds, mfa_creds_ldap)

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
        :param ip: IP address
        :param user_agent: str
        :return: RedirectResponse
        :raises HTTPException: 404 if not found
        """
        try:
            return await self._manager.callback_mfa(
                access_token, mfa_creds, ip, user_agent
            )
        except MFATokenError:
            from fastapi.responses import RedirectResponse

            return RedirectResponse("/mfa_token_error", status.HTTP_302_FOUND)
        except NotFoundError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from e

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
        :param ip: IP address
        :param user_agent: str
        :return: MFAChallengeResponse
        :raises HTTPException: 422 if invalid credentials or not found
        :raises HTTPException: 403 if forbidden
            (missing API credentials, network policy violation, etc.)
        :raises HTTPException: 406 if MFA error
        """
        try:
            return await self._manager.two_factor_protocol(
                form, request, response, ip, user_agent
            )
        except InvalidCredentialsError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            )
        except (
            MissingMFACredentialsError,
            NetworkPolicyError,
            ForbiddenError,
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN)
        except NotFoundError:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY)
        except MFAError as exc:
            raise HTTPException(
                status.HTTP_406_NOT_ACCEPTABLE,
                detail=str(exc),
            )
