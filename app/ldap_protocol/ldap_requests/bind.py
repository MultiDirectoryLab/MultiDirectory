"""LDAP requests bind."""
from abc import ABC, abstractmethod
from enum import Enum
from typing import AsyncGenerator, ClassVar

from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, Session
from ldap_protocol.ldap_responses import BaseResponse, BindResponse
from ldap_protocol.multifactor import MultifactorAPI
from ldap_protocol.utils import get_user, is_user_group_valid
from models.ldap3 import Group, MFAFlags, User
from security import verify_password

from .base import BaseRequest


class SASLMethod(str, Enum):
    """SASL choices."""

    PLAIN = "PLAIN"
    EXTERNAL = "EXTERNAL"
    GSSAPI = "GSSAPI"
    CRAM_MD5 = "CRAM-MD5"
    DIGEST_MD5 = "DIGEST-MD5"
    SCRAM_SHA_1 = "SCRAM-SHA-1"
    SCRAM_SHA_256 = "SCRAM-SHA-256"
    OAUTHBEARER = "OAUTHBEARER"
    UNBOUNDID_CERTIFICATE_PLUS_PASSWORD = "UNBOUNDID-CERTIFICATE-PLUS-PASSWORD"
    UNBOUNDID_TOTP = "UNBOUNDID-TOTP"
    UNBOUNDID_DELIVERED_OTP = "UNBOUNDID-DELIVERED-OTP"
    UNBOUNDID_YUBIKEY_OTP = "UNBOUNDID-YUBIKEY-OTP"


class AbstractLDAPAuth(ABC, BaseModel):
    """Auth base class."""

    @property
    @abstractmethod
    def METHOD_ID(self) -> int:  # noqa: N802, D102
        """Abstract method id."""

    @abstractmethod
    def is_valid(self, user: User):
        """Validate state."""

    @abstractmethod
    def is_anonymous(self):
        """Return true if anonymous."""


class SimpleAuthentication(AbstractLDAPAuth):
    """Simple auth form."""

    METHOD_ID: ClassVar[int] = 0

    password: str

    def is_valid(self, user: User | None) -> bool:
        """Check if pwd is valid for user.

        :param User | None user: indb user
        :return bool: status
        """
        password = getattr(user, "password", None)
        return bool(password) and verify_password(self.password, password)

    def is_anonymous(self) -> bool:
        """Check if auth is anonymous.

        :return bool: status
        """
        return not self.password


class SaslAuthentication(AbstractLDAPAuth):
    """Sasl auth form."""

    METHOD_ID: ClassVar[int] = 3

    mechanism: SASLMethod
    credentials: bytes


class BindRequest(BaseRequest):
    """Bind request fields mapping."""

    PROTOCOL_OP: ClassVar[int] = 0x0

    version: int
    name: str
    authentication_choice: SimpleAuthentication | SaslAuthentication =\
        Field(..., alias='AuthenticationChoice')

    @classmethod
    def from_data(cls, data) -> 'BindRequest':
        """Get bind from data dict."""
        auth = data[2].tag_id.value

        if auth == SimpleAuthentication.METHOD_ID:
            auth_choice = SimpleAuthentication(password=data[2].value)
        elif auth == SaslAuthentication.METHOD_ID:  # noqa: R506
            raise NotImplementedError
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
    async def is_user_group_valid(user, ldap_session, session) -> bool:
        """Test compability."""
        return await is_user_group_valid(user, ldap_session.policy, session)

    async def check_mfa(
            self, user: User,
            ldap_session: Session, session: AsyncSession) -> BindResponse:
        """Check mfa api.

        :param User user: db user
        :param Session ldap_session: ldap session
        :param AsyncSession session: db session
        :return BindResponse: response
        """
        if user.is_mfa_set_up is False:
            return self.BAD_RESPONSE

        key, secret = await MultifactorAPI.get_auth(session)
        api = MultifactorAPI(
            key, secret,
            client=ldap_session.client,
            settings=ldap_session.settings,
        )
        try:
            mfa_status = api.ldap_validate_mfa(
                user.display_name,
                self.authentication_choice.password)
        except MultifactorAPI.MultifactorError as err:
            return BindResponse(
                result_code=LDAPCodes.INAPPROPRIATE_AUTHENTICATION,
                errorMessage=str(err), matchedDn='')
        else:
            if mfa_status is False:
                return self.BAD_RESPONSE

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[BindResponse, None]:
        """Handle bind request, check user and password."""
        if not self.name and self.authentication_choice.is_anonymous():
            yield BindResponse(result_code=LDAPCodes.SUCCESS)
            return
        user = await get_user(session, self.name)

        if not user or not self.authentication_choice.is_valid(user):
            yield self.BAD_RESPONSE
            return

        if not await self.is_user_group_valid(user, ldap_session, session):
            yield self.BAD_RESPONSE
            return

        if policy := getattr(ldap_session, 'policy', None):
            if policy.mfa_status == MFAFlags.ENABLED:
                if user.is_mfa_set_up is False:
                    yield self.BAD_RESPONSE
                    return

                yield self.check_mfa(user, ldap_session, session)
                return

            if policy.mfa_status == MFAFlags.WHITELIST:
                group = await session.scalar(select(Group).filter(
                    Group.mfa_policies.contains(policy),
                    Group.users.contains(user),
                ))
                if not group or (group and not user.is_mfa_set_up):
                    yield self.BAD_RESPONSE
                    return

                yield self.check_mfa(user, ldap_session, session)
                return

        await ldap_session.set_user(user)

        yield BindResponse(result_code=LDAPCodes.SUCCESS, matchedDn='')


class UnbindRequest(BaseRequest):
    """Remove user from ldap_session."""

    PROTOCOL_OP: ClassVar[int] = 2

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'UnbindRequest':
        """Unbind request has no body."""
        return cls()

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[BaseResponse, None]:
        """Handle unbind request, no need to send response."""
        await ldap_session.delete_user()
        return  # declare empty async generator and exit
        yield
