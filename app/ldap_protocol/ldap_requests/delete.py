"""Delete protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import joinedload

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    DeleteResponse,
)
from ldap_protocol.utils import (
    get_path_filter,
    get_search_path,
    validate_entry,
)
from models.ldap3 import Directory

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

    async def handle(
        self, session: AsyncSession,
        ldap_session: LDAPSession,
        kadmin: AbstractKadmin,
    ) -> AsyncGenerator[DeleteResponse, None]:
        """Delete request handler."""
        if not ldap_session.user:
            yield DeleteResponse(**INVALID_ACCESS_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield DeleteResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        search_path = get_search_path(self.entry)

        query = select(Directory)\
            .join(Directory.path)\
            .options(joinedload(Directory.user))\
            .filter(get_path_filter(search_path))

        obj = await session.scalar(query)
        if not obj:
            yield DeleteResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        if obj.user:
            try:
                await kadmin.del_principal(obj.user.get_upn_prefix())
            except KRBAPIError:
                pass

        await session.delete(obj)
        await session.commit()

        yield DeleteResponse(result_code=LDAPCodes.SUCCESS)
