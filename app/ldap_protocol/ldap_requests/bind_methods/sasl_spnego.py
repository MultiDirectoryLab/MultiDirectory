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
    """Sasl SPNEGO auth method.

    Implements SPNEGO (RFC 4178) as a negotiation wrapper around GSS-API.
    In practice the negotiated mechanism is Kerberos.

    Flow:

    1. Negotiation & Context Initialization:
        - The server acquires acceptor credentials from keytab using the
            ldap/{REALM} service principal.
        - Creates a GSS-API acceptor security context with the SPNEGO
            mechanism (which in turn negotiates Kerberos).
        - Stores the context in the LDAP session.

    2. Intermediate Request:
        - The client and server may exchange several SPNEGO tokens
            (NegTokenResp with responseToken/mechListMIC) until the wrapped
            GSS (Kerberos) context becomes established.
        - When `server_ctx.complete` becomes true, the initiator principal
            is available via `ctx.initiator_name` and server sends NegTokenResp
            with success.

    """

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
        if server_ctx is None or self.ticket == b"":
            return get_bad_response(LDAPBindErrors.LOGON_FAILURE)

        status = self._handle_ticket(server_ctx)

        if not server_ctx.complete:
            return BindResponse(
                result_code=LDAPCodes.SASL_BIND_IN_PROGRESS,
                server_sasl_creds=self.server_sasl_creds,
            )

        if status == GSSAPIAuthStatus.SEND_TO_CLIENT:
            self._ldap_session.gssapi_authenticated = True
            self._ldap_session.gssapi_security_layer = GSSAPISL.CONFIDENTIALITY
            return None

        return get_bad_response(LDAPBindErrors.LOGON_FAILURE)
