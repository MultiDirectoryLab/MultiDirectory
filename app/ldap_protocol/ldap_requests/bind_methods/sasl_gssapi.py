"""Sasl GSSAPI auth method.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, StrEnum
from typing import ClassVar

import gssapi
from pydantic import Field, SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import BindResponse
from ldap_protocol.utils.queries import get_base_directories, get_user
from models import User

from .base import (
    LDAPBindErrors,
    SaslAuthentication,
    SASLMethod,
    get_bad_response,
)


class GSSAPISL(IntEnum):
    """GSSAPI security layers, described in in RFC4752 section 3.3."""

    NO_SECURITY = 1
    INTEGRITY_PROTECTION = 2
    CONFIDENTIALITY = 4

    SUPPORTED_SECURITY_LAYERS = (
        NO_SECURITY
        | INTEGRITY_PROTECTION
        | CONFIDENTIALITY
    )


class GSSAPIAuthStatus(StrEnum):
    """GSSAPI auth status."""

    SEND_TO_CLIENT = "SEND_TO_CLIENT"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"


class SaslGSSAPIAuthentication(SaslAuthentication):
    """Sasl GSSAPI auth form.

    Full GSSAPI authentication flow. Describe in rfc4752:

    1. Context Initialization Phase:
    - The server acquires credentials from keytab using ldap/{REALM}
        principal
    - Creates security context with default kerberos mechanisms
    - Stores context in LDAP session

    2. Intermediate Requests:
    - The client sends kerberos AP-REQ token
    - The server processes token
    - Сontinues until context is established
    - The client sends empty token

    3. Final Handshake:
    - The server wraps and sends the message:
        * First octet: bitmask of supported security layers
        * Next 3 octets: max output size the server is able to recieve
    - The client sends wrapped message with:
        * First octet: bitmask of selected security layer
        * Next 3 octets: client maximum buffer size
    """

    mechanism: ClassVar[SASLMethod] = SASLMethod.GSSAPI
    password: SecretStr = Field(default=SecretStr(""))
    server_sasl_creds: bytes = b""
    ticket: bytes = b""
    ldap_session: LDAPSession | None = None

    class Config:
        """Pydantic config."""

        arbitrary_types_allowed = True

    def is_valid(self, user: User | None) -> bool:
        """Check if GSSAPI token is valid.

        :param User | None user: indb user
        :return bool: status
        """
        return True

    def is_anonymous(self) -> bool:
        """Check if auth is anonymous.

        :return bool: status
        """
        return False

    @classmethod
    def from_data(cls, data: list[ASN1Row]) -> "SaslGSSAPIAuthentication":
        """Get auth from data.

        :param list[ASN1Row] data: data
        :return SaslGSSAPIAuthentication
        """
        return cls(
            ticket=data[1].value if len(data) > 1 else b"",
        )

    async def _init_security_context(
        self,
        session: AsyncSession,
        ldap_session: LDAPSession,
        settings: Settings,
    ) -> None:
        """Init security context.

        :param AsyncSession session: db session
        :param LDAPSession ldap_session: ldap session
        :param Settings settings: settings
        """
        base_dn_list = await get_base_directories(session)
        base_dn = base_dn_list[0].name

        server_name = gssapi.Name(
            f"ldap/{base_dn}@{base_dn.upper()}",
            gssapi.NameType.krb5_nt_principal_name,
        )

        server_creds = gssapi.Credentials(
            name=server_name,
            usage="accept",
            store={"keytab": settings.KRB5_LDAP_KEYTAB},
            mechs=[gssapi.MechType.kerberos],
        )

        ldap_session.gssapi_security_context = gssapi.SecurityContext(
            creds=server_creds,
        )

    def _handle_ticket(
        self, server_ctx: gssapi.SecurityContext,
    ) -> GSSAPIAuthStatus:
        """Handle the ticket and make gssapi step.

        :param gssapi.SecurityContext server_ctx: GSSAPI security context
        :return GSSAPIAuthStatus: status
        """
        try:
            out_token = server_ctx.step(self.ticket)
            self.server_sasl_creds = out_token
            return GSSAPIAuthStatus.SEND_TO_CLIENT
        except gssapi.exceptions.GSSError:
            return GSSAPIAuthStatus.ERROR

    def _validate_security_layer(
        self, client_layer: GSSAPISL, settings: Settings,
    ) -> bool:
        """Validate security layer.

        :param int client_layer: client security layer
        :param Settings settings: settings
        :return bool: validate result
        """
        supported = GSSAPISL.SUPPORTED_SECURITY_LAYERS
        return (client_layer & supported) == client_layer

    def _handle_final_client_message(
        self,
        server_ctx: gssapi.SecurityContext,
        ldap_session: LDAPSession,
        settings: Settings,
    ) -> GSSAPIAuthStatus:
        """Handle final client message.

        :param gssapi.SecurityContext server_ctx: GSSAPI security context
        :param LDAPSession ldap_session: ldap session
        :param Settings settings: settings
        :return GSSAPIAuthStatus: status
        """
        try:
            unwrap_message = server_ctx.unwrap(self.ticket)
            if len(unwrap_message.message) == 4:
                client_security_layer = GSSAPISL(
                    int.from_bytes(
                        unwrap_message.message[:1],
                    ),
                )
                if self._validate_security_layer(
                    client_security_layer, settings,
                ):
                    ldap_session.gssapi_authenticated = True
                    ldap_session.gssapi_security_layer = client_security_layer
                    return GSSAPIAuthStatus.COMPLETE
            return GSSAPIAuthStatus.ERROR
        except gssapi.exceptions.GSSError:
            return GSSAPIAuthStatus.ERROR

    def _generate_final_message(
        self, server_ctx: gssapi.SecurityContext, settings: Settings,
    ) -> bytes:
        """Generate final wrap message.

        :param gssapi.SecurityContext server_ctx: gssapi context
        :param Settings settings: settings
        :return bytes: message
        """
        max_size = settings.GSSAPI_MAX_OUTPUT_TOKEN_SIZE
        if GSSAPISL.SUPPORTED_SECURITY_LAYERS == GSSAPISL.NO_SECURITY:
            max_size = 0  # type: ignore

        message = (
            GSSAPISL.SUPPORTED_SECURITY_LAYERS.to_bytes() +
            max_size.to_bytes(length=3)
        )

        wrap_message = server_ctx.wrap(message, encrypt=False)
        return wrap_message.message

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
        if not ldap_session.gssapi_security_context:
            await self._init_security_context(
                session, ldap_session, settings,
            )

        server_ctx = ldap_session.gssapi_security_context
        if server_ctx is None:
            return get_bad_response(LDAPBindErrors.LOGON_FAILURE)

        if self.ticket == b"":
            self.server_sasl_creds = self._generate_final_message(
                server_ctx, settings,
            )
            return BindResponse(
                result_code=LDAPCodes.SASL_BIND_IN_PROGRESS,
                server_sasl_creds=self.server_sasl_creds,
            )

        if server_ctx.complete:
            status = self._handle_final_client_message(
                server_ctx, ldap_session, settings,
            )
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

    async def get_user(  # type: ignore
        self,
        session: AsyncSession,
        name: str,
    ) -> User | None:
        """Get user.

        :param gssapi.SecurityContext ctx: gssapi context
        :param AsyncSession session: db session
        """
        if not self.ldap_session:
            return None

        ctx = self.ldap_session.gssapi_security_context
        if not ctx:
            return None

        username = str(ctx.initiator_name).split('@')[0]
        return await get_user(session, username)  # type: ignore
