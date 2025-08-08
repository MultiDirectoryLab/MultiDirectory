"""Delete protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from sqlalchemy import delete, select
from sqlalchemy.orm import defaultload, selectinload

from enums import AceType
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.kerberos import KRBAPIError
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    DeleteResponse,
)
from ldap_protocol.objects import ProtocolRequests
from ldap_protocol.utils.helpers import is_dn_in_base_directory
from ldap_protocol.utils.queries import (
    get_base_directories,
    get_filter_from_path,
    is_computer,
    validate_entry,
)
from models import Directory, Group

from .base import BaseRequest
from .contexts import LDAPDeleteRequestContext


class DeleteRequest(BaseRequest):
    """Delete request.

    DelRequest ::= [APPLICATION 10] LDAPDN
    """

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.DELETE

    entry: str

    @classmethod
    def from_data(cls, data: ASN1Row) -> "DeleteRequest":
        return cls(entry=data)

    async def handle(
        self,
        ctx: LDAPDeleteRequestContext,
    ) -> AsyncGenerator[DeleteResponse, None]:
        """Delete request handler."""
        if not ctx.ldap_session.user:
            yield DeleteResponse(**INVALID_ACCESS_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield DeleteResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        if not ctx.ldap_session.user.role_ids:
            yield DeleteResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
            return

        query = (
            select(Directory)
            .options(
                defaultload(Directory.user),
                selectinload(Directory.groups).selectinload(Group.directory),
                defaultload(Directory.attributes),
            )
            .filter(get_filter_from_path(self.entry))
        )

        query = ctx.access_manager.mutate_query_with_ace_load(
            user_role_ids=ctx.ldap_session.user.role_ids,
            query=query,
            ace_types=[AceType.DELETE],
            require_attribute_type_null=True,
        )

        directory = await ctx.session.scalar(query)

        if not directory:
            yield DeleteResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        self.set_event_data(
            {"before_attrs": self.get_directory_attrs(directory)},
        )

        if directory.is_domain:
            yield DeleteResponse(result_code=LDAPCodes.UNWILLING_TO_PERFORM)
            return

        can_delete = ctx.access_manager.check_entity_level_access(
            aces=directory.access_control_entries,
            entity_type_id=directory.entity_type_id,
        )

        if not can_delete:
            yield DeleteResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
            return

        for base_directory in await get_base_directories(ctx.session):
            if is_dn_in_base_directory(base_directory, self.entry):
                base_dn = base_directory
                break

        try:
            if directory.user:
                await ctx.kadmin.del_principal(directory.user.get_upn_prefix())
                await ctx.session_storage.clear_user_sessions(
                    directory.user.id,
                )

            if await is_computer(directory.id, ctx.session):
                await ctx.kadmin.del_principal(directory.host_principal)
                await ctx.kadmin.del_principal(
                    f"{directory.host_principal}.{base_dn.name}",
                )
        except KRBAPIError:
            yield DeleteResponse(
                result_code=LDAPCodes.UNAVAILABLE,
                errorMessage="KerberosError",
            )
            return

        await ctx.session.execute(delete(Directory).filter_by(id=directory.id))
        await ctx.session.commit()

        yield DeleteResponse(result_code=LDAPCodes.SUCCESS)
