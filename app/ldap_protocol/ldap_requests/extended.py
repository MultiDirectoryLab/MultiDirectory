"""Extended request."""

from abc import ABC, abstractmethod
from typing import AsyncGenerator, ClassVar

from asn1 import Decoder
from loguru import logger
from pydantic import BaseModel, SerializeAsAny
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import LDAPOID, ASN1Row, asn1todict
from ldap_protocol.dialogue import LDAPCodes, Session
from ldap_protocol.ldap_responses import (
    BaseExtendedResponseValue,
    ExtendedResponse,
)
from ldap_protocol.utils import get_user
from models import Attribute, User, Directory
from security import get_password_hash, verify_password

from .base import BaseRequest


class BaseExtendedValue(ABC, BaseModel):
    """Base extended request body."""

    REQUEST_ID: ClassVar[LDAPOID]

    @classmethod
    @abstractmethod
    def from_data(cls, data: ASN1Row) -> 'BaseExtendedValue':
        """Create model from data, decoded from responseValue bytes."""

    @abstractmethod
    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            BaseExtendedResponseValue:
        """Generate specific extended resoponse."""


class PasswdModifyResponse(BaseExtendedResponseValue):
    """Password modify response.

    PasswdModifyResponseValue ::= SEQUENCE {
        genPasswd       [0]     OCTET STRING OPTIONAL }
    """

    gen_passwd: str = ''


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
            PasswdModifyResponse:
        """Update password of current or selected user."""
        if not ldap_session.settings.USE_CORE_TLS:
            raise PermissionError('TLS required')

        if self.user_identity is not None:
            user = await get_user(session, self.user_identity)
            if not user:
                raise PermissionError('Cannot acquire user by DN')
        else:
            if not ldap_session.user:
                raise PermissionError('Anonymous user')

            user = await session.get(User, ldap_session.user.id)

        if verify_password(self.old_password, user.password):
            user.password = get_password_hash(self.new_password)
            await session.execute(  # update bind reject attribute
                update(Attribute)
                .values({'value': '1'})
                .where(
                    Attribute.directory_id == user.directory_id,
                    Attribute.name == 'pwdLastSet',
                    Attribute.value == '0',
                ))
            await session.execute(
                update(Directory).where(Directory.id == user.directory_id),
            )
            await session.commit()
            return PasswdModifyResponse()
        raise PermissionError('No user provided')

    @classmethod
    def from_data(cls, data: ASN1Row) -> \
            'PasswdModifyRequestValue':
        """Create model from data, decoded from responseValue bytes."""
        if len(data) == 3:
            return cls(
                user_identity=data[0].value,
                old_password=data[1].value,
                new_password=data[2].value,
            )

        return cls(old_password=data[0].value, new_password=data[1].value)


EXTENDED_REQUEST_OID_MAP = {
    req.REQUEST_ID: req for req in
    [PasswdModifyRequestValue]
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
        try:
            response = await self.request_value.handle(ldap_session, session)
        except PermissionError as err:
            logger.critical(err)  # noqa
            yield ExtendedResponse(
                result_code=LDAPCodes.OPERATIONS_ERROR,
                response_name=self.request_name,
                response_value=None,
            )
        else:
            yield ExtendedResponse(
                result_code=LDAPCodes.SUCCESS,
                response_name=self.request_name,
                response_value=response,
            )

    @classmethod
    def from_data(cls, data: ASN1Row) -> 'ExtendedRequest':
        """Create extended request from asn.1 decoded string.

        :param ASN1Row data: any data
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
