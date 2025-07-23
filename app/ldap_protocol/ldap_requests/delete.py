"""Delete protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from enums import AceType
from sqlalchemy import Select, and_, delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defaultload, selectinload, with_loader_criteria

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    DeleteResponse,
)
from ldap_protocol.roles.access_manager import AccessManager
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.utils.helpers import is_dn_in_base_directory
from ldap_protocol.utils.queries import (
    get_base_directories,
    get_filter_from_path,
    is_computer,
    validate_entry,
)
from models import AccessControlEntry, Directory

from .base import BaseRequest


class DeleteRequest(BaseRequest):
    """Delete request.

    DelRequest ::= [APPLICATION 10] LDAPDN
    """

    PROTOCOL_OP: ClassVar[int] = 10

    entry: str

    @classmethod
    def from_data(cls, data: ASN1Row) -> "DeleteRequest":
        return cls(entry=data)

    def _mutate_query_with_ace_load(
        self, user_role_ids: list[int], query: Select
    ) -> Select:
        """Mutate query to load access control entries.

        :param user_role_ids: list of user role ids
        :param query: SQLAlchemy query to mutate
        :return: mutated query with access control entries loaded
        """
        return query.options(
            selectinload(Directory.access_control_entries),
            with_loader_criteria(
                AccessControlEntry,
                and_(
                    AccessControlEntry.role_id.in_(user_role_ids),
                    AccessControlEntry.ace_type == AceType.DELETE,
                    AccessControlEntry.attribute_type_id.is_(None),
                ),
            ),
        )

    async def handle(
        self,
        session: AsyncSession,
        ldap_session: LDAPSession,
        kadmin: AbstractKadmin,
        session_storage: SessionStorage,
        access_manager: AccessManager,
    ) -> AsyncGenerator[DeleteResponse, None]:
        """Delete request handler."""
        if not ldap_session.user:
            yield DeleteResponse(**INVALID_ACCESS_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield DeleteResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        if not ldap_session.user.role_ids:
            yield DeleteResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS
            )
            return

        query = (
            select(Directory)
            .options(
                defaultload(Directory.user),
                defaultload(Directory.attributes),
            )
            .filter(get_filter_from_path(self.entry))
        )

        query = self._mutate_query_with_ace_load(
            ldap_session.user.role_ids, query
        )

        directory = await session.scalar(query)

        if not directory:
            yield DeleteResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        if directory.is_domain:
            yield DeleteResponse(result_code=LDAPCodes.UNWILLING_TO_PERFORM)
            return

        can_delete = access_manager.check_entity_level_access(
            aces=directory.access_control_entries,
            entity_type_id=directory.entity_type_id,
        )

        if not can_delete:
            yield DeleteResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
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
