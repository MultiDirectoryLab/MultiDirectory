"""Extended request."""

from abc import ABC, abstractmethod
from typing import AsyncGenerator, ClassVar

from pydantic import BaseModel, SerializeAsAny
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import LDAPOID
from ldap_protocol.dialogue import Session
from ldap_protocol.ldap_responses import (
    BaseExtendedResponseValue,
    ExtendedResponse,
)

from .base import BaseRequest


class BaseExtendedValue(ABC, BaseModel):
    """Base extended request body."""

    request_id: ClassVar[LDAPOID]

    @abstractmethod
    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[BaseExtendedResponseValue, None]:
        """Generate specific extended resoponse."""


class PasswdModifyRsponse(BaseExtendedResponseValue):
    pass


class PasswdModifyRequestValue(BaseExtendedValue):
    """Described in RFC3062.

    The Password Modify operation is an LDAPv3 Extended Operation
    [RFC2251, Section 4.12] and is identified by the OBJECT IDENTIFIER
    passwdModifyOID.  This section details the syntax of the protocol
    request and response.

    passwdModifyOID OBJECT IDENTIFIER ::= 1.3.6.1.4.1.4203.1.11.1

    PasswdModifyRequestValue ::= SEQUENCE {
        userIdentity    [0]  OCTET STRING OPTIONAL
        oldPasswd       [1]  OCTET STRING OPTIONAL
        newPasswd       [2]  OCTET STRING OPTIONAL }

    PasswdModifyResponseValue ::= SEQUENCE {
        genPasswd       [0]     OCTET STRING OPTIONAL }
    """

    request_id: ClassVar[LDAPOID] = "1.3.6.1.4.1.4203.1.11.1"

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[PasswdModifyRsponse, None]:
        pass


class ExtendedRequest(BaseRequest):
    """Extended protocol.

    ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
        requestName      [0] LDAPOID,
        requestValue     [1] OCTET STRING OPTIONAL }
    """

    PROTOCOL_OP: ClassVar[int] = 23
    request_name: LDAPOID
    request_value: SerializeAsAny[BaseExtendedValue]

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[ExtendedResponse, None]:
        """Call proxy handler."""
        yield await self.request_value.handle(ldap_session, session)
