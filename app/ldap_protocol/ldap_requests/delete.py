"""Delete protocol."""

from typing import AsyncGenerator, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, Session
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    DeleteResponse,
)
from ldap_protocol.utils import is_base_dn, validate_entry
from models.ldap3 import Directory, Path

from .base import BaseRequest


class DeleteRequest(BaseRequest):
    """Delete request.

    DelRequest ::= [APPLICATION 10] LDAPDN
    """

    PROTOCOL_OP: ClassVar[int] = 10

    entry: str

    @classmethod
    def from_data(cls, data: ASN1Row) -> 'DeleteRequest':  # noqa: D102
        return cls(entry=data)

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[DeleteResponse, None]:
        """Delete request handler."""
        if not ldap_session.user:
            yield DeleteResponse(**INVALID_ACCESS_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield DeleteResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        if await is_base_dn(session, self.entry):
            yield DeleteResponse(result_code=LDAPCodes.UNWILLING_TO_PERFORM)
            return

        search_path = reversed(self.entry.lower().split(','))

        query = select(Directory)\
            .join(Directory.path)\
            .filter(Path.path == search_path)

        obj = await session.scalar(query)
        if not obj:
            yield DeleteResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        await session.delete(obj)
        await session.commit()

        yield DeleteResponse(result_code=LDAPCodes.SUCCESS)
