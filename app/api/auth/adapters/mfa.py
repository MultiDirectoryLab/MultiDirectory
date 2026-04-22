"""FastAPI adapter for MFAManager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from fastapi import status
from fastapi.responses import RedirectResponse

from api.auth.schemas import MFACreateRequest, MFAGetResponse
from api.base_adapter import BaseAdapter
from ldap_protocol.auth import MFAManager
from ldap_protocol.auth.dto import MFACreateRequestDTO
from ldap_protocol.auth.exceptions.mfa import MFATokenError
from ldap_protocol.multifactor import MFA_HTTP_Creds, MFA_LDAP_Creds


class MFAFastAPIAdapter(BaseAdapter[MFAManager]):
    """Adapter for using MFAManager with FastAPI."""

    async def setup_mfa(self, mfa: MFACreateRequest) -> bool:
        """Create or update MFA keys.

        :param mfa: MFACreateRequest
        :return: bool
        """
        return await self._service.setup_mfa(
            MFACreateRequestDTO(
                mfa_key=mfa.mfa_key,
                mfa_secret=mfa.mfa_secret,
                is_ldap_scope=mfa.is_ldap_scope,
                key_name=mfa.key_name,
                secret_name=mfa.secret_name,
            )
        )

    async def remove_mfa(self, scope: str) -> None:
        """Delete MFA keys by scope.

        :param scope: str ('http' or 'ldap')
        :return: None
        """
        await self._service.remove_mfa(scope)

    async def get_mfa(self, mfa_creds: MFA_HTTP_Creds, mfa_creds_ldap: MFA_LDAP_Creds) -> MFAGetResponse:
        """Get MFA keys for http and ldap.

        :param mfa_creds: MFA_HTTP_Creds
        :param mfa_creds_ldap: MFA_LDAP_Creds
        :return: MFAGetResponse
        """
        mfa_get_response = await self._service.get_mfa(mfa_creds, mfa_creds_ldap)
        return MFAGetResponse(
            mfa_key=mfa_get_response.mfa_key,
            mfa_secret=mfa_get_response.mfa_secret,
            mfa_key_ldap=mfa_get_response.mfa_key_ldap,
            mfa_secret_ldap=mfa_get_response.mfa_secret_ldap,
        )

    async def callback_mfa(
        self, access_token: str, mfa_creds: MFA_HTTP_Creds, ip: IPv4Address | IPv6Address, user_agent: str
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
            key = await self._service.callback_mfa(access_token, mfa_creds, ip, user_agent)
            response = RedirectResponse("/", 302)
            self._service.set_new_session_key(key)
            return response
        except MFATokenError:
            return RedirectResponse("/mfa_token_error", status.HTTP_302_FOUND)
