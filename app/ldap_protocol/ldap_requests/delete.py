"""Delete protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defaultload

from ldap_protocol.access_policy import mutate_ap
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    DeleteResponse,
)
from ldap_protocol.utils.helpers import is_dn_in_base_directory
from ldap_protocol.utils.queries import (
    get_base_directories,
    get_filter_from_path,
    is_computer,
    validate_entry,
)
from models import Directory

from .base import BaseRequest


class DeleteRequest(BaseRequest):
    """Delete request.

    DelRequest ::= [APPLICATION 10] LDAPDN
    """

    PROTOCOL_OP: ClassVar[int] = 10

    entry: str

    @classmethod
    def from_data(cls, data: ASN1Row) -> "DeleteRequest":  # noqa: D102
        return cls(entry=data)

    async def handle(
        self,
        session: AsyncSession,
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

        query = (
            select(Directory)
            .options(
                defaultload(Directory.user),
                defaultload(Directory.attributes),
            )
            .filter(get_filter_from_path(self.entry))
        )

        directory = await session.scalar(mutate_ap(query, ldap_session.user))

        if not directory:
            yield DeleteResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        if not await session.scalar(
            mutate_ap(query, ldap_session.user, "del"),
        ):
            yield DeleteResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
            return

        if directory.is_domain:
            yield DeleteResponse(result_code=LDAPCodes.UNWILLING_TO_PERFORM)
            return

        for base_directory in await get_base_directories(session):
            if is_dn_in_base_directory(base_directory, self.entry):
                base_dn = base_directory
                break

        try:
            if directory.user:
                await kadmin.del_principal(directory.user.get_upn_prefix())

            if await is_computer(directory.id, session):
                await kadmin.del_principal(directory.host_principal)
                await kadmin.del_principal(
                    f"{directory.host_principal}.{base_dn.name}",
                )
        except KRBAPIError:
            yield DeleteResponse(
                result_code=LDAPCodes.UNAVAILABLE,
                errorMessage="KerberosError",
            )
            return

        await session.delete(directory)
        await session.commit()

        yield DeleteResponse(result_code=LDAPCodes.SUCCESS)
