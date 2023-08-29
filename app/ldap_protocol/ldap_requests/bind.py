"""LDAP requests bind."""
from abc import ABC, abstractmethod
from typing import AsyncGenerator, ClassVar

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, Session
from ldap_protocol.ldap_responses import BaseResponse, BindResponse
from ldap_protocol.utils import get_user
from models.ldap3 import User
from security import verify_password

from .base import BaseRequest


class AuthChoice(ABC, BaseModel):
    """Auth base class."""

    @abstractmethod
    def is_valid(self, user: User):
        """Validate state."""

    @abstractmethod
    def is_anonymous(self):
        """Return true if anonymous."""


class SimpleAuthentication(AuthChoice):
    """Simple auth form."""

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


class SaslAuthentication(AuthChoice):
    """Sasl auth form."""

    mechanism: str
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

        if auth == 0:
            auth_choice = SimpleAuthentication(password=data[2].value)
        elif auth == 3:  # noqa: R506
            raise NotImplementedError('Sasl not supported')  # TODO: Add SASL
        else:
            raise ValueError('Auth version not supported')

        return cls(
            version=data[0].value,
            name=data[1].value,
            AuthenticationChoice=auth_choice,
        )

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[BindResponse, None]:
        """Handle bind request, check user and password."""
        if not self.name and self.authentication_choice.is_anonymous():
            yield BindResponse(result_code=LDAPCodes.SUCCESS)
            return

        bad_response = BindResponse(
            result_code=LDAPCodes.INVALID_CREDENTIALS,
            matchedDN='',
            errorMessage=(
                '80090308: LdapErr: DSID-0C090447, '
                'comment: AcceptSecurityContext error, '
                'data 52e, v3839'),
        )
        user = await get_user(session, self.name)

        if not user or not self.authentication_choice.is_valid(user):
            yield bad_response
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
