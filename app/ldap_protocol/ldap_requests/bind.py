"""LDAP requests bind.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import AsyncGenerator, ClassVar

import gssapi
import httpx
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from config import GSSAPISL, Settings
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import BaseResponse, BindResponse
from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from ldap_protocol.policies.network_policy import (
    check_mfa_group,
    is_user_group_valid,
)
from ldap_protocol.policies.password_policy import PasswordPolicySchema
from ldap_protocol.user_account_control import (
    UserAccountControlFlag,
    get_check_uac,
)
from ldap_protocol.utils.queries import (
    check_kerberos_group,
    get_base_directories,
    get_user,
    set_last_logon_user,
)
from models import MFAFlags, NetworkPolicy, User
from security import verify_password

from .base import BaseRequest


class SASLMethod(StrEnum):
    """SASL choices."""

    PLAIN = "PLAIN"
    EXTERNAL = "EXTERNAL"
    GSSAPI = "GSSAPI"
    CRAM_MD5 = "CRAM-MD5"
    DIGEST_MD5 = "DIGEST-MD5"
    SCRAM_SHA_1 = "SCRAM-SHA-1"
    SCRAM_SHA_256 = "SCRAM-SHA-256"
    OAUTHBEARER = "OAUTHBEARER"
    UNBOUNDID_CERTIFICATE_PLUS_PASSWORD = "UNBOUNDID-CERTIFICATE-PLUS-PASSWORD"  # noqa
    UNBOUNDID_TOTP = "UNBOUNDID-TOTP"
    UNBOUNDID_DELIVERED_OTP = "UNBOUNDID-DELIVERED-OTP"
    UNBOUNDID_YUBIKEY_OTP = "UNBOUNDID-YUBIKEY-OTP"


class GSSAPIAuthStatus(StrEnum):
    """GSSAPI auth status."""

    SEND_TO_CLIENT = "SEND_TO_CLIENT"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"


class LDAPBindErrors(StrEnum):
    """LDAP Bind errors."""

    NO_SUCH_USER = "525"
    LOGON_FAILURE = "52e"
    INVALID_LOGON_HOURS = "530"
    INVALID_WORKSTATION = "531"
    PASSWORD_EXPIRED = "532"  # noqa
    ACCOUNT_DISABLED = "533"
    ACCOUNT_EXPIRED = "701"
    PASSWORD_MUST_CHANGE = "773"  # noqa
    ACCOUNT_LOCKED_OUT = "775"

    def __str__(self) -> str:  # noqa
        return (
            "80090308: LdapErr: DSID-0C09030B, "
            "comment: AcceptSecurityContext error, "
            f"data {self.value}, v893"
        )


def get_bad_response(error_message: LDAPBindErrors) -> BindResponse:
    """Generate BindResponse object with an invalid credentials error.

    :param LDAPBindErrors error_message: Error message to include in the
                                         response
    :return BindResponse: A response object with the result code set to
                          INVALID_CREDENTIALS, an empty matchedDN, and the
                          provided error message
    """
    return BindResponse(
        result_code=LDAPCodes.INVALID_CREDENTIALS,
        matchedDN="",
        errorMessage=str(error_message),
    )


class AbstractLDAPAuth(ABC, BaseModel):
    """Auth base class."""

    otpassword: str | None = Field(None, max_length=6, min_length=6)
    password: SecretStr

    @property
    @abstractmethod
    def METHOD_ID(self) -> int:  # noqa: N802, D102
        """Abstract method id."""

    @abstractmethod
    def is_valid(self, user: User) -> bool:
        """Validate state."""

    @abstractmethod
    def is_anonymous(self) -> bool:
        """Return true if anonymous."""

    @abstractmethod
    async def get_user(self, session: AsyncSession, username: str) -> User:
        """Get user."""


class SimpleAuthentication(AbstractLDAPAuth):
    """Simple auth form."""

    METHOD_ID: ClassVar[int] = 0

    def is_valid(self, user: User | None) -> bool:
        """Check if pwd is valid for user.

        :param User | None user: indb user
        :return bool: status
        """
        password = getattr(user, "password", None)
        if password is not None:
            return verify_password(self.password.get_secret_value(), password)
        return False

    def is_anonymous(self) -> bool:
        """Check if auth is anonymous.

        :return bool: status
        """
        return not self.password

    async def get_user(self, session: AsyncSession, username: str) -> User:
        """Get user."""
        return await get_user(session, username)  # type: ignore


class SaslAuthentication(AbstractLDAPAuth):
    """Sasl auth form."""

    METHOD_ID: ClassVar[int] = 3
    mechanism: ClassVar[SASLMethod]

    @classmethod
    @abstractmethod
    def from_data(cls, data: list[ASN1Row]) -> "SaslAuthentication":
        """Get auth from data."""


class SaslPLAINAuthentication(SaslAuthentication):
    """Sasl plain auth form."""

    mechanism: ClassVar[SASLMethod] = SASLMethod.PLAIN
    credentials: bytes
    username: str | None = None

    def is_valid(self, user: User | None) -> bool:
        """Check if pwd is valid for user.

        :param User | None user: indb user
        :return bool: status
        """
        password = getattr(user, "password", None)
        if password is not None:
            return verify_password(
                self.password.get_secret_value(), password,
            )
        return False

    def is_anonymous(self) -> bool:
        """Check if auth is anonymous.

        :return bool: status
        """
        return False

    @classmethod
    def from_data(cls, data: list[ASN1Row]) -> "SaslPLAINAuthentication":
        """Get auth from data."""
        _, username, password = data[1].value.split("\\x00")
        return cls(
            credentials=data[1].value,
            username=username,
            password=password,
        )

    async def get_user(self, session: AsyncSession, _: str) -> User:
        """Get user."""
        return await get_user(session, self.username)  # type: ignore


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
        supported = settings.GSSAPI_SUPPORTED_SECURITY_LAYERS
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
        if settings.GSSAPI_SUPPORTED_SECURITY_LAYERS == GSSAPISL.NO_SECURITY:
            max_size = 0

        message = (
            settings.GSSAPI_SUPPORTED_SECURITY_LAYERS.to_bytes() +
            max_size.to_bytes(length=3)
        )

        wrap_message = server_ctx.wrap(message, encrypt=False)
        return wrap_message.message

    async def step(
        self,
        session: AsyncSession,
        ldap_session: LDAPSession,
        settings: Settings,
    ) -> GSSAPIAuthStatus:
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
            return GSSAPIAuthStatus.ERROR

        if self.ticket == b"":
            self.server_sasl_creds = self._generate_final_message(
                server_ctx, settings,
            )
            return GSSAPIAuthStatus.SEND_TO_CLIENT

        if server_ctx.complete:
            return self._handle_final_client_message(
                server_ctx, ldap_session, settings,
            )

        return self._handle_ticket(server_ctx)

    async def get_user(
        self,
        ctx: gssapi.SecurityContext,  # type: ignore
        session: AsyncSession,  # type: ignore
    ) -> User:
        """Get user.

        :param gssapi.SecurityContext ctx: gssapi context
        :param AsyncSession session: db session
        """
        username = str(ctx.initiator_name).split('@')[0]
        return await get_user(session, username)  # type: ignore


sasl_mechanism: list[type[SaslAuthentication]] = [
    SaslPLAINAuthentication,
    SaslGSSAPIAuthentication,
]

sasl_mechanism_map: dict[SASLMethod, type[SaslAuthentication]] = {
    request.mechanism: request for request in sasl_mechanism
}


class BindRequest(BaseRequest):
    """Bind request fields mapping."""

    PROTOCOL_OP: ClassVar[int] = 0x0

    version: int
    name: str
    authentication_choice: AbstractLDAPAuth = Field(
        ..., alias="AuthenticationChoice",
    )

    @classmethod
    def from_data(cls, data: list[ASN1Row]) -> "BindRequest":
        """Get bind from data dict."""
        auth = data[2].tag_id

        otpassword: str | None
        auth_choice: AbstractLDAPAuth

        if auth == SimpleAuthentication.METHOD_ID:
            payload: str = data[2].value

            password = payload[:-6]
            otpassword = payload.removeprefix(password)

            if not otpassword.isdecimal():
                otpassword = None
                password = payload

            auth_choice = SimpleAuthentication(
                password=password,
                otpassword=otpassword,
            )
        elif auth == SaslAuthentication.METHOD_ID:  # noqa: R506
            sasl_method = data[2].value[0].value
            auth_choice = sasl_mechanism_map[sasl_method].from_data(
                data[2].value,
            )
        else:
            raise ValueError("Auth version not supported")

        return cls(
            version=data[0].value,
            name=data[1].value,
            AuthenticationChoice=auth_choice,
        )

    @staticmethod
    async def is_user_group_valid(
        user: User, ldap_session: LDAPSession, session: AsyncSession,
    ) -> bool:
        """Test compability."""
        return await is_user_group_valid(user, ldap_session.policy, session)

    @staticmethod
    async def check_mfa(
        api: MultifactorAPI | None,
        identity: str,
        otp: str | None,
        policy: NetworkPolicy,
    ) -> bool:
        """Check mfa api.

        :param User user: db user
        :param LDAPSession ldap_session: ldap session
        :param AsyncSession session: db session
        :return bool: response
        """
        if api is None:
            return False

        try:
            return await api.ldap_validate_mfa(identity, otp)
        except MultifactorAPI.MFAConnectError:
            if policy.bypass_no_connection:
                return True
            return False
        except MultifactorAPI.MFAMissconfiguredError:
            return True
        except MultifactorAPI.MultifactorError:
            if policy.bypass_service_failure:
                return True
            return False

    async def handle(
        self,
        session: AsyncSession,
        ldap_session: LDAPSession,
        kadmin: AbstractKadmin,
        settings: Settings,
        mfa: LDAPMultiFactorAPI,
    ) -> AsyncGenerator[BindResponse, None]:
        """Handle bind request, check user and password."""
        if not self.name and self.authentication_choice.is_anonymous():
            yield BindResponse(result_code=LDAPCodes.SUCCESS)
            return

        if isinstance(self.authentication_choice, SaslGSSAPIAuthentication):
            action = await self.authentication_choice.step(
                session,
                ldap_session,
                settings,
            )

            if action == GSSAPIAuthStatus.SEND_TO_CLIENT:
                yield BindResponse(
                    result_code=LDAPCodes.SASL_BIND_IN_PROGRESS,
                    server_sasl_creds=(
                        self.authentication_choice.server_sasl_creds
                    ),
                )
                return
            if (
                action == GSSAPIAuthStatus.ERROR or
                not ldap_session.gssapi_security_context
            ):
                yield get_bad_response(LDAPBindErrors.LOGON_FAILURE)
                return

            user = await self.authentication_choice.get_user(
                ldap_session.gssapi_security_context,
                session,
            )

        else:
            user = await self.authentication_choice.get_user(
                session, self.name,
            )

        if not user or not self.authentication_choice.is_valid(user):
            yield get_bad_response(LDAPBindErrors.LOGON_FAILURE)
            return

        uac_check = await get_check_uac(session, user.directory_id)

        if uac_check(UserAccountControlFlag.ACCOUNTDISABLE):
            yield get_bad_response(LDAPBindErrors.ACCOUNT_DISABLED)
            return

        if not await self.is_user_group_valid(user, ldap_session, session):
            yield get_bad_response(LDAPBindErrors.LOGON_FAILURE)
            return

        policy = await PasswordPolicySchema.get_policy_settings(
            session, kadmin,
        )
        p_last_set = await policy.get_pwd_last_set(session, user.directory_id)
        pwd_expired = policy.validate_max_age(p_last_set)

        is_krb_user = await check_kerberos_group(user, session)

        required_pwd_change = (
            p_last_set == "0" or pwd_expired
        ) and not is_krb_user

        if user.is_expired():
            yield get_bad_response(LDAPBindErrors.ACCOUNT_EXPIRED)
            return

        if required_pwd_change:
            yield get_bad_response(LDAPBindErrors.PASSWORD_MUST_CHANGE)
            return

        if policy := getattr(ldap_session, "policy", None):  # type: ignore
            if policy.mfa_status in (MFAFlags.ENABLED, MFAFlags.WHITELIST):

                request_2fa = True
                if policy.mfa_status == MFAFlags.WHITELIST:
                    request_2fa = await check_mfa_group(policy, user, session)

                if request_2fa:
                    mfa_status = await self.check_mfa(
                        mfa,
                        user.user_principal_name,
                        self.authentication_choice.otpassword,
                        policy,
                    )

                    if mfa_status is False:
                        yield get_bad_response(LDAPBindErrors.LOGON_FAILURE)
                        return

        try:
            await kadmin.add_principal(
                user.get_upn_prefix(),
                self.authentication_choice.password.get_secret_value(),
                0.1,
            )
        except (KRBAPIError, httpx.TimeoutException):
            pass

        await ldap_session.set_user(user)
        await set_last_logon_user(user, session, settings.TIMEZONE)

        yield BindResponse(result_code=LDAPCodes.SUCCESS)


class UnbindRequest(BaseRequest):
    """Remove user from ldap_session."""

    PROTOCOL_OP: ClassVar[int] = 2

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> "UnbindRequest":
        """Unbind request has no body."""
        return cls()

    async def handle(
        self, ldap_session: LDAPSession,
    ) -> AsyncGenerator[BaseResponse, None]:
        """Handle unbind request, no need to send response."""
        await ldap_session.delete_user()
        return  # declare empty async generator and exit
        yield  # type: ignore
