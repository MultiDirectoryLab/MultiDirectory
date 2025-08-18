"""FastAPI adapter for MFAManager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from fastapi import Request, Response, status
from fastapi.responses import RedirectResponse

from api.auth.adapters.cookie_mixin import ResponseCookieMixin
from api.auth.schema import (
    MFAChallengeResponse,
    MFACreateRequest,
    MFAGetResponse,
    OAuth2Form,
)
from api.base_adapter import BaseAdapter
from api.exceptions.mfa import (
    ForbiddenError,
    InvalidCredentialsError,
    MFAError,
    MFATokenError,
    MissingMFACredentialsError,
    NetworkPolicyError,
    NotFoundError,
)
from ldap_protocol.identity import MFAManager
from ldap_protocol.multifactor import MFA_HTTP_Creds, MFA_LDAP_Creds


class MFAFastAPIAdapter(ResponseCookieMixin, BaseAdapter[MFAManager]):
    """Adapter for using MFAManager with FastAPI."""

    _exceptions_map: dict[type[Exception], int] = {
        MissingMFACredentialsError: status.HTTP_403_FORBIDDEN,
        NetworkPolicyError: status.HTTP_403_FORBIDDEN,
        ForbiddenError: status.HTTP_403_FORBIDDEN,
        InvalidCredentialsError: status.HTTP_422_UNPROCESSABLE_ENTITY,
        NotFoundError: status.HTTP_404_NOT_FOUND,
        MFAError: status.HTTP_406_NOT_ACCEPTABLE,
        MFATokenError: status.HTTP_302_FOUND,
    }

    async def setup_mfa(self, mfa: MFACreateRequest) -> bool:
        """Create or update MFA keys.

        :param mfa: MFACreateRequest
        :return: bool
        """
        return await self._service.setup_mfa(mfa)

    async def remove_mfa(self, scope: str) -> None:
        """Delete MFA keys by scope.

        :param scope: str ('http' or 'ldap')
        :return: None
        """
        await self._service.remove_mfa(scope)

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
        return await self._service.get_mfa(mfa_creds, mfa_creds_ldap)

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
        :raises HTTPException: 302 redirect if MFA token error
        """
        try:
            key = await self._service.callback_mfa(
                access_token,
                mfa_creds,
                ip,
                user_agent,
            )
            response = RedirectResponse("/", 302)
            await self.set_session_cookie(
                response,
                self._service.key_ttl,
                key,
            )
            return response
        except MFATokenError:
            return RedirectResponse("/mfa_token_error", status.HTTP_302_FOUND)

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
        result, key = await self._service.two_factor_protocol(
            form=form,
            url=request.url_for("callback_mfa"),
            ip=ip,
            user_agent=user_agent,
        )
        if key is not None:
            await self.set_session_cookie(
                response,
                self._service.key_ttl,
                key,
            )
        return result
