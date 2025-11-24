"""FastAPI adapter for MFAManager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from fastapi import status
from fastapi.responses import RedirectResponse

from api.base_adapter import BaseAdapter
from ldap_protocol.auth import MFAManager
from ldap_protocol.auth.exceptions.mfa import (
    ForbiddenError,
    InvalidCredentialsError,
    MFAAPIError,
    MFAConnectError,
    MFATokenError,
    MissingMFACredentialsError,
    NetworkPolicyError,
    NotFoundError,
)
from ldap_protocol.auth.schemas import MFACreateRequest, MFAGetResponse
from ldap_protocol.multifactor import MFA_HTTP_Creds, MFA_LDAP_Creds


class MFAFastAPIAdapter(BaseAdapter[MFAManager]):
    """Adapter for using MFAManager with FastAPI."""

    _exceptions_map: dict[type[Exception], int] = {
        MissingMFACredentialsError: status.HTTP_403_FORBIDDEN,
        NetworkPolicyError: status.HTTP_403_FORBIDDEN,
        ForbiddenError: status.HTTP_403_FORBIDDEN,
        InvalidCredentialsError: status.HTTP_422_UNPROCESSABLE_ENTITY,
        NotFoundError: status.HTTP_404_NOT_FOUND,
        MFAAPIError: status.HTTP_406_NOT_ACCEPTABLE,
        MFAConnectError: status.HTTP_406_NOT_ACCEPTABLE,
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
            self._service.set_new_session_key(key)
            return response
        except MFATokenError:
            return RedirectResponse("/mfa_token_error", status.HTTP_302_FOUND)
