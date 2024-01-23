"""Extended request."""

from abc import ABC, abstractmethod
from typing import AsyncGenerator, ClassVar

from asn1 import Decoder
from pydantic import BaseModel, SerializeAsAny
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import LDAPOID, ASN1Row, asn1todict
from ldap_protocol.dialogue import Session
from ldap_protocol.ldap_responses import (
    BaseExtendedResponseValue,
    ExtendedResponse,
)

from .base import BaseRequest


class BaseExtendedValue(ABC, BaseModel):
    """Base extended request body."""

    REQUEST_ID: ClassVar[LDAPOID]

    @classmethod
    @abstractmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'BaseExtendedValue':
        """Create model from data, decoded from responseValue bytes."""

    @abstractmethod
    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[BaseExtendedResponseValue, None]:
        """Generate specific extended resoponse."""


class PasswdModifyResponse(BaseExtendedResponseValue):
    """Password modify response.

    PasswdModifyResponseValue ::= SEQUENCE {
        genPasswd       [0]     OCTET STRING OPTIONAL }
    """

    gen_passwd: str


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
    """

    REQUEST_ID: ClassVar[LDAPOID] = "1.3.6.1.4.1.4203.1.11.1"
    user_identity: str | None = None
    old_password: str
    new_password: str

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[PasswdModifyResponse, None]:
        return PasswdModifyResponse(gen_passwd=self.new_password)

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> \
            'PasswdModifyRequestValue':
        """Create model from data, decoded from responseValue bytes."""
        return cls(old_password=data[0].value, new_password=data[1].value)


EXTENDED_REQUEST_OID_MAP = {
    PasswdModifyRequestValue.REQUEST_ID: PasswdModifyRequestValue,
}


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
        response = await self.request_value.handle(ldap_session, session)
        yield ExtendedResponse(
            result_code=0,
            response_name=self.request_name,
            response_value=response,
        )

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'ExtendedRequest':
        """Create extended request from asn.1 decoded string.

        :param dict[str, list[ASN1Row]] data: any data
        :return ExtendedRequest: universal request
        """
        dec = Decoder()
        dec.start(data[1].value)
        output = asn1todict(dec)

        oid = data[0].value
        ext_request = EXTENDED_REQUEST_OID_MAP[oid]

        return cls(
            request_name=oid,
            request_value=ext_request.from_data(output[0].value),
        )
