"""Modify DN request.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from sqlalchemy import func, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from ldap_protocol.access_policy import mutate_read_access_policy
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, LDAPSession
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    ModifyDNResponse,
)
from ldap_protocol.utils import (
    get_base_directories,
    get_filter_from_path,
    get_path_filter,
    is_dn_in_base_directory,
    validate_entry,
)
from models.ldap3 import AccessPolicy, Directory, DirectoryReferenceMixin, Path

from .base import BaseRequest


class ModifyDNRequest(BaseRequest):
    """Update DN.

    ```
    ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
        entry           LDAPDN,
        newrdn          RelativeLDAPDN,
        deleteoldrdn    BOOLEAN,
        newSuperior     [0] LDAPDN OPTIONAL
    }
    ```

    **entry** — The current DN for the target entry.

    **newrdn** — The new RDN to use assign to the entry.
        It may be the same as the
        current RDN if you only intend to move the entry beneath a new parent.
        If the new RDN includes any attribute values that arent
        already in the entry, the entry will be updated to include them.

    **deleteoldrdn** — Indicates whether to delete any attribute values from
        the entry that were in the original RDN but not in the new RDN.

    **newSuperior** — The DN of the entry that should become the new
        parent for the entry (and any of its subordinates).
        This is optional, and if it is omitted, then the entry will be
        left below the same parent and only the RDN will be altered.

    **example**:

        entry='cn=main,dc=multifactor,dc=dev'
        newrdn='cn=main2'
        deleteoldrdn=true
        new_superior='ou=users,dc=multifactor,dc=dev'

        >>> cn=main2,ou=users,dc=multifactor,dc=dev
    """

    PROTOCOL_OP: ClassVar[int] = 12

    entry: str
    newrdn: str
    deleteoldrdn: bool
    new_superior: str | None

    @classmethod
    def from_data(cls, data: ASN1Row) -> 'ModifyDNResponse':
        """Create structure from ASN1Row dataclass list."""
        return cls(
            entry=data[0].value,
            newrdn=data[1].value,
            deleteoldrdn=data[2].value,
            new_superior=None if len(data) < 4 else data[3].value,
        )

    async def handle(
        self, ldap_session: LDAPSession, session: AsyncSession,
    ) -> AsyncGenerator[ModifyDNResponse, None]:
        """Handle message with current user."""
        if not ldap_session.user:
            yield ModifyDNResponse(**INVALID_ACCESS_RESPONSE)
            return

        if any([
            not validate_entry(self.entry),
            self.new_superior and not validate_entry(self.new_superior),
            not validate_entry(self.newrdn),
        ]):
            yield ModifyDNResponse(resultCode=LDAPCodes.INVALID_DN_SYNTAX)
            return

        query = select(Directory)\
            .join(Directory.path)\
            .options(selectinload(Directory.paths))\
            .options(selectinload(Directory.parent))\
            .filter(get_filter_from_path(self.entry))  # noqa

        query = mutate_read_access_policy(query, ldap_session.user)

        directory: Directory | None = await session.scalar(query)

        if not directory:
            yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        if directory.is_domain:
            yield ModifyDNResponse(result_code=LDAPCodes.UNWILLING_TO_PERFORM)
            return

        for base_directory in await get_base_directories(session):
            if is_dn_in_base_directory(base_directory, self.entry):
                base_dn = base_directory
                break
        else:
            yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        if not await session.scalar(
                query.where(AccessPolicy.can_modify.is_(True))):
            yield ModifyDNResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS)
            return

        dn, name = self.newrdn.split('=')

        if self.new_superior is None:
            new_directory = Directory(
                name=name,
                object_class=directory.object_class,
                depth=directory.depth,
                parent_id=directory.parent_id,
                created_at=directory.created_at,
                object_guid=directory.object_guid,
                object_sid=directory.object_sid,
            )
            new_path = new_directory.create_path(directory.parent, dn)

        elif base_dn.path_dn == self.new_superior:
            new_directory = Directory(
                object_class=directory.object_class,
                name=name,
                depth=len(base_dn.path.path)+1,
                object_guid=directory.object_guid,
                object_sid=directory.object_sid,
            )
            new_path = new_directory.create_path(parent=base_dn, dn=dn)

        else:
            new_sup_query = select(Directory)\
                .join(Directory.path)\
                .options(selectinload(Directory.path))\
                .filter(get_filter_from_path(self.new_superior))

            new_sup_query = mutate_read_access_policy(
                new_sup_query, ldap_session.user)

            new_sup_query.filter(AccessPolicy.can_read())

            new_base_directory = await session.scalar(new_sup_query)

            if not new_base_directory:
                yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
                return

            if not await session.scalar(
                    query.where(AccessPolicy.can_add.is_(True))):
                yield ModifyDNResponse(
                    result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS)
                return

            new_directory = Directory(
                object_class=directory.object_class,
                name=name,
                parent=new_base_directory,
                depth=len(new_base_directory.path.path)+1,
                object_guid=directory.object_guid,
                object_sid=directory.object_sid,
            )
            new_path = new_directory.create_path(new_base_directory, dn=dn)

        async with session.begin_nested():
            session.add_all([new_directory, new_path])
            await session.commit()

        async with session.begin_nested():
            await session.execute(
                update(Directory)
                .where(Directory.parent == directory)
                .values(parent_id=new_directory.id))

            await session.commit()

        async with session.begin_nested():
            for model in DirectoryReferenceMixin.__subclasses__():
                await session.execute(
                    update(model)
                    .where(model.directory_id == directory.id)
                    .values(directory_id=new_directory.id))

        async with session.begin_nested():
            #  TODO: replace text with slice
            await session.execute(
                update(Path)
                .where(
                    get_path_filter(
                        directory.path.path,
                        column=Path.path[1:directory.depth],
                    ),
                )
                .values(
                    path=func.array_cat(
                        new_directory.path.path,
                        text("path[:depth :]").bindparams(
                            depth=directory.depth+1),
                    ),
                ),
                execution_options={"synchronize_session": 'fetch'},
            )
            await session.commit()

        await session.refresh(directory)
        await session.delete(directory)
        await session.commit()

        yield ModifyDNResponse(result_code=LDAPCodes.SUCCESS)
