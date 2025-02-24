"""Delete protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defaultload

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    DeleteResponse,
)
from ldap_protocol.objects import ProtocolRequests
from ldap_protocol.policies.access_policy import mutate_ap
from ldap_protocol.session_storage import SessionStorage
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

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.DELETE

    entry: str

    @classmethod
    def from_data(cls, data: ASN1Row) -> "DeleteRequest":
        return cls(entry=data)

    async def to_event_data(self, session: AsyncSession) -> dict:  # noqa: D102
        directory = await session.scalar((
            select(Directory)
            .options(defaultload(Directory.attributes))
            .filter(get_filter_from_path(self.entry))
        ))

        attributes: dict[str, list[str]] = {}
        if directory:
            for attribute in directory.attributes:
                if attribute.name not in attributes:
                    attributes[attribute.name] = []

                if attribute.value:
                    value = attribute.value
                elif attribute.bvalue:
                    value = attribute.bvalue.decode(errors="replace")
                else:
                    raise AttributeError

                attributes[attribute.name].append(value)

        return {
            "entry": self.entry,
            "attributes": attributes,
        }

    async def handle(
        self,
        session: AsyncSession,
        ldap_session: LDAPSession,
        kadmin: AbstractKadmin,
        session_storage: SessionStorage,
        *args: tuple,
        **kwargs: dict,
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
                await session_storage.clear_user_sessions(directory.user.id)

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

        await session.execute(delete(Directory).filter_by(id=directory.id))
        await session.commit()

        yield DeleteResponse(result_code=LDAPCodes.SUCCESS)
