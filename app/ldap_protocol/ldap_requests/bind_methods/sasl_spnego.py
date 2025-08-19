"""Sasl SPNEGO auth method.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import BindResponse

from .base import LDAPBindErrors, SASLMethod, get_bad_response
from .sasl_gssapi import GSSAPISL, GSSAPIAuthStatus, SaslGSSAPIAuthentication


class SaslSPNEGOAuthentication(SaslGSSAPIAuthentication):
    """Sasl SPNEGO auth method."""

    mechanism: ClassVar[SASLMethod] = SASLMethod.GSS_SPNEGO

    async def step(
        self,
        session: AsyncSession,
        ldap_session: LDAPSession,
        settings: Settings,
    ) -> BindResponse | None:
        """GSSAPI step.

        :param AsyncSession session: db session
        :param LDAPSession ldap_session: ldap session
        :param Settings settings: settings
        """
        self._ldap_session = ldap_session

        if not self._ldap_session.gssapi_security_context:
            await self._init_security_context(session, settings)

        server_ctx = self._ldap_session.gssapi_security_context
        if server_ctx is None:
            return get_bad_response(LDAPBindErrors.LOGON_FAILURE)

        if self.ticket == b"":
            self.server_sasl_creds = self._generate_final_message(
                server_ctx,
                settings,
            )
            self._ldap_session.gssapi_authenticated = True
            self._ldap_session.gssapi_security_layer = GSSAPISL.CONFIDENTIALITY
            return None

        if server_ctx.complete:
            status = self._handle_final_client_message(server_ctx)
            if status == GSSAPIAuthStatus.COMPLETE:
                return None

            return get_bad_response(LDAPBindErrors.LOGON_FAILURE)

        status = self._handle_ticket(server_ctx)

        if status == GSSAPIAuthStatus.SEND_TO_CLIENT:
            return BindResponse(
                result_code=LDAPCodes.SASL_BIND_IN_PROGRESS,
                server_sasl_creds=self.server_sasl_creds,
            )
        return get_bad_response(LDAPBindErrors.LOGON_FAILURE)
