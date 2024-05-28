"""Modify DN request.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from sqlalchemy import func, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, Session
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    ModifyDNResponse,
)
from ldap_protocol.utils import get_base_dn, get_path_filter, get_search_path
from models.ldap3 import Directory, DirectoryReferenceMixin, Path

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
    new_superior: str

    @classmethod
    def from_data(cls, data: ASN1Row) -> 'ModifyDNResponse':
        """Create structure from ASN1Row dataclass list."""
        return cls(
            entry=data[0].value,
            newrdn=data[1].value,
            deleteoldrdn=data[2].value,
            new_superior=data[3].value,
        )

    async def handle(self, ldap_session: Session, session: AsyncSession) ->\
            AsyncGenerator[ModifyDNResponse, None]:
        """Handle message with current user."""
        if not ldap_session.user:
            yield ModifyDNResponse(**INVALID_ACCESS_RESPONSE)
            return

        base_dn = await get_base_dn(session)
        obj = get_search_path(self.entry, base_dn)

        query = select(Directory)\
            .join(Directory.path)\
            .options(selectinload(Directory.paths))\
            .filter(get_path_filter(obj))

        new_sup = get_search_path(self.new_superior, base_dn)
        new_sup_query = select(Directory)\
            .join(Directory.path)\
            .options(selectinload(Directory.path))\
            .filter(get_path_filter(new_sup))

        directory = await session.scalar(query)

        if not directory:
            yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        dn_is_base = self.new_superior.lower() == base_dn.lower()
        dn, name = self.newrdn.split('=')
        if dn_is_base:
            new_directory = Directory(
                object_class=directory.object_class,
                name=name,
                depth=1,
            )
            new_path = new_directory.create_path(dn=dn)
        else:
            new_base_directory = await session.scalar(new_sup_query)
            if not new_base_directory:
                yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
                return

            new_directory = Directory(
                object_class=directory.object_class,
                name=name,
                parent=new_base_directory,
                depth=len(new_base_directory.path.path)+1,
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

        old_path_str = ','.join(directory.path.path)
        new_path_str = ','.join(new_directory.path.path)

        async with session.begin_nested():
            await session.execute(
                update(Path)
                .where(
                    func.array_to_string(Path.path, ',').like(
                        f"{old_path_str},%"),
                )
                .values(
                    path=func.string_to_array(
                        func.replace(
                            func.array_to_string(Path.path, ','),
                            old_path_str,
                            new_path_str,
                        ),
                        ',',
                    ),
                ),
                execution_options={"synchronize_session": 'fetch'},
            )
            await session.commit()

        await session.refresh(directory)
        await session.delete(directory)
        await session.commit()

        yield ModifyDNResponse(result_code=LDAPCodes.SUCCESS)
