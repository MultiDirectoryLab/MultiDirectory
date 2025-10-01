"""Delete protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from sqlalchemy import delete, exists, select
from sqlalchemy.orm import joinedload, selectinload

from entities import Directory, Group
from enums import AceType
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.kerberos import KRBAPIError, KRBAPIPrincipalNotFoundError
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
from repo.pg.tables import Attribute, queryable_attr as qa

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
                joinedload(qa(Directory.user)),
                selectinload(qa(Directory.groups)).selectinload(
                    qa(Group.directory),
                ),
                joinedload(qa(Directory.group)).selectinload(
                    qa(Group.members),
                ),
                selectinload(qa(Directory.attributes)),
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

        if directory.group:
            primary_group_members_query = exists(Attribute).where(
                Attribute.name == "primaryGroupID",
                Attribute.value == directory.relative_id,
            )
            if await ctx.session.scalar(select(primary_group_members_query)):
                yield DeleteResponse(
                    result_code=LDAPCodes.ENTRY_ALREADY_EXISTS,
                    error_message=(
                        "Can't delete group with members having"
                        " it as primary group."
                    ),
                )
                return

        has_access_to_delete = ctx.access_manager.check_entity_level_access(
            aces=directory.access_control_entries,
            entity_type_id=directory.entity_type_id,
        )

        if not has_access_to_delete:
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
                if directory.path_dn == ctx.ldap_session.user.dn:
                    yield DeleteResponse(
                        result_code=LDAPCodes.OPERATIONS_ERROR,
                        error_message="Cannot delete yourself.",
                    )
                    return
                await ctx.session_storage.clear_user_sessions(
                    directory.user.id,
                )
                await ctx.kadmin.del_principal(directory.user.get_upn_prefix())

            if await is_computer(directory.id, ctx.session):
                await ctx.kadmin.del_principal(directory.host_principal)
                await ctx.kadmin.del_principal(
                    f"{directory.host_principal}.{base_dn.name}",
                )
        except KRBAPIPrincipalNotFoundError:
            pass
        except KRBAPIError:
            yield DeleteResponse(
                result_code=LDAPCodes.UNAVAILABLE,
                errorMessage="KerberosError",
            )
            return

        await ctx.session.execute(delete(Directory).filter_by(id=directory.id))
        await ctx.session.commit()

        yield DeleteResponse(result_code=LDAPCodes.SUCCESS)
