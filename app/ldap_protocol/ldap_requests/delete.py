"""Delete protocol."""

from typing import AsyncGenerator, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from ldap_protocol.dialogue import LDAPCodes, Session
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    DeleteResponse,
)
from ldap_protocol.utils import get_base_dn, validate_entry
from models.ldap3 import Directory, Path

from .base import BaseRequest


class DeleteRequest(BaseRequest):
    """Delete request.

    DelRequest ::= [APPLICATION 10] LDAPDN
    """

    PROTOCOL_OP: ClassVar[int] = 10

    entry: str

    @classmethod
    def from_data(cls, data):  # noqa: D102
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

        base_dn = await get_base_dn(session)
        obj = self.entry.lower().removesuffix(
            ',' + base_dn.lower()).split(',')
        search_path = reversed(obj)

        query = select(Directory)\
            .join(Directory.path)\
            .options(selectinload(Directory.paths))\
            .filter(Path.path == search_path)

        obj = await session.scalar(query)
        if not obj:
            yield DeleteResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        await session.delete(obj)
        await session.commit()

        yield DeleteResponse(result_code=LDAPCodes.SUCCESS)