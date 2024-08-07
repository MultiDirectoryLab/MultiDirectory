"""LDAP requests bind.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import AsyncGenerator, ClassVar

from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_responses import BaseResponse, BindResponse
from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from ldap_protocol.password_policy import PasswordPolicySchema
from ldap_protocol.utils import (
    get_user,
    is_user_group_valid,
    set_last_logon_user,
)
from models.ldap3 import Group, MFAFlags, User
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
    async def get_user(self, session: LDAPSession, username: str) -> User:
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
        return bool(password) and verify_password(
            self.password.get_secret_value(), password)

    def is_anonymous(self) -> bool:
        """Check if auth is anonymous.

        :return bool: status
        """
        return not self.password

    async def get_user(self, session: LDAPSession, username: str) -> User:
        """Get user."""
        return await get_user(session, username)


class SaslAuthentication(AbstractLDAPAuth):
    """Sasl auth form."""

    METHOD_ID: ClassVar[int] = 3
    mechanism: ClassVar[SASLMethod]

    @classmethod
    @abstractmethod
    def from_data(cls, data: list[ASN1Row]) -> 'SaslPLAINAuthentication':
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
        return bool(password) and verify_password(
            self.password.get_secret_value(), password)

    def is_anonymous(self) -> bool:
        """Check if auth is anonymous.

        :return bool: status
        """
        return False

    @classmethod
    def from_data(cls, data: list[ASN1Row]) -> 'SaslPLAINAuthentication':
        """Get auth from data."""
        _, username, password = data[1].value.split('\\x00')
        return cls(
            credentials=data[1].value,
            username=username,
            password=password,
        )

    async def get_user(self, session: LDAPSession, _: str) -> User:
        """Get user."""
        return await get_user(session, self.username)


sasl_mechanism: list[type[SaslAuthentication]] = [
    SaslPLAINAuthentication,
]

sasl_mechanism_map: dict[SASLMethod, type[SaslAuthentication]] = {
    request.mechanism: request for request in sasl_mechanism
}


class BindRequest(BaseRequest):
    """Bind request fields mapping."""

    PROTOCOL_OP: ClassVar[int] = 0x0

    version: int
    name: str
    authentication_choice: AbstractLDAPAuth =\
        Field(..., alias='AuthenticationChoice')

    @classmethod
    def from_data(cls, data: ASN1Row) -> 'BindRequest':
        """Get bind from data dict."""
        auth = data[2].tag_id.value

        otpassword: str | None

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
            auth_choice = sasl_mechanism_map[
                sasl_method].from_data(data[2].value)  # type: ignore
        else:
            raise ValueError('Auth version not supported')

        return cls(
            version=data[0].value,
            name=data[1].value,
            AuthenticationChoice=auth_choice,
        )

    BAD_RESPONSE: ClassVar[BindResponse] = BindResponse(
        result_code=LDAPCodes.INVALID_CREDENTIALS,
        matchedDN='',
        errorMessage=(
            '80090308: LdapErr: DSID-0C090447, '
            'comment: AcceptSecurityContext error, '
            'data 52e, v3839'),
    )

    @staticmethod
    async def is_user_group_valid(
            user: User,
            ldap_session: LDAPSession,
            session: AsyncSession) -> bool:
        """Test compability."""
        return await is_user_group_valid(user, ldap_session.policy, session)

    @staticmethod
    async def check_mfa(
        api: MultifactorAPI | None,
        identity: str,
        otp: str | None,
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
        except MultifactorAPI.MultifactorError:
            return False

    async def handle(
        self, session: AsyncSession,
        ldap_session: LDAPSession,
        kadmin: AbstractKadmin,
        settings: Settings,
        mfa: LDAPMultiFactorAPI,
    ) -> AsyncGenerator[BindResponse, None]:
        """Handle bind request, check user and password."""
        if not self.name and self.authentication_choice.is_anonymous():
            yield BindResponse(result_code=LDAPCodes.SUCCESS)
            return

        user = await self.authentication_choice.get_user(session, self.name)

        if not user or not self.authentication_choice.is_valid(user):
            yield self.BAD_RESPONSE
            return

        if not await self.is_user_group_valid(user, ldap_session, session):
            yield self.BAD_RESPONSE
            return

        policy = await PasswordPolicySchema.get_policy_settings(session)
        p_last_set = await policy.get_pwd_last_set(session, user.directory_id)
        pwd_expired = policy.validate_max_age(p_last_set)

        required_pwd_change = p_last_set == '0' or pwd_expired

        if required_pwd_change:
            yield BindResponse(
                result_code=LDAPCodes.INVALID_CREDENTIALS,
                matchedDn='',
                errorMessage=(
                    "80090308: LdapErr: DSID-0C09030B, "
                    "comment: AcceptSecurityContext error, "
                    "data 773, v893"))
            return

        if policy := getattr(ldap_session, 'policy', None):
            if policy.mfa_status in (MFAFlags.ENABLED, MFAFlags.WHITELIST):

                check_group = True

                if policy.mfa_status == MFAFlags.WHITELIST:
                    check_group = await session.scalar(select(exists().where(
                        Group.mfa_policies.contains(policy),
                        Group.users.contains(user),
                    )))  # type: ignore

                if check_group:
                    mfa_status = await self.check_mfa(
                        mfa,
                        user.user_principal_name,
                        self.authentication_choice.otpassword)

                    if mfa_status is False:
                        yield self.BAD_RESPONSE
                        return

        try:
            await kadmin.add_principal(
                user.get_upn_prefix(),
                self.authentication_choice.password.get_secret_value())
        except KRBAPIError:
            pass

        await ldap_session.set_user(user)
        await set_last_logon_user(
            user, session, settings.TIMEZONE)

        yield BindResponse(result_code=LDAPCodes.SUCCESS, matchedDn='')


class UnbindRequest(BaseRequest):
    """Remove user from ldap_session."""

    PROTOCOL_OP: ClassVar[int] = 2

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'UnbindRequest':
        """Unbind request has no body."""
        return cls()

    async def handle(self, ldap_session: LDAPSession) -> \
            AsyncGenerator[BaseResponse, None]:
        """Handle unbind request, no need to send response."""
        await ldap_session.delete_user()
        return  # declare empty async generator and exit
        yield  # type: ignore
