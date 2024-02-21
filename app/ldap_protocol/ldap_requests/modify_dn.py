"""Modify DN request."""

from typing import AsyncGenerator, ClassVar

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, Session
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    ModifyDNResponse,
)
from ldap_protocol.utils import get_base_dn
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

    entry — The current DN for the target entry.
    newrdn — The new RDN to use assign to the entry. It may be the same as the
        current RDN if you only intend to move the entry beneath a new parent.
        If the new RDN includes any attribute values that arent
        already in the entry, the entry will be updated to include them.
    deleteoldrdn — Indicates whether to delete any attribute values from the
        entry that were in the original RDN but not in the new RDN.
    newSuperior — The DN of the entry that should become the new
        parent for the entry (and any of its subordinates).
        This is optional, and if it is omitted, then the entry will be
        left below the same parent and only the RDN will be altered.

    example:
        entry='cn=main,dc=multifactor,dc=dev'
        newrdn='cn=main2'
        deleteoldrdn=True
        new_superior='dc=multifactor,dc=dev'
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
        obj = self.entry.lower().removesuffix(
            ',' + base_dn.lower()).split(',')

        query = select(Directory)\
            .join(Directory.path)\
            .options(selectinload(Directory.paths))\
            .filter(Path.path == reversed(obj))

        new_sup = self.new_superior.lower().removesuffix(
            ',' + base_dn.lower()).split(',')

        new_sup_query = select(Directory)\
            .join(Directory.path)\
            .options(selectinload(Directory.path))\
            .filter(Path.path == reversed(new_sup))

        directory = await session.scalar(query)

        if not directory:
            yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        dn_is_base = self.new_superior.lower() == base_dn.lower()
        if dn_is_base:
            new_directory = Directory(
                object_class='',
                name=self.newrdn.split('=')[1],
            )
            new_path = new_directory.create_path()
        else:
            new_base_directory = await session.scalar(new_sup_query)
            if not new_base_directory:
                yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
                return

            new_directory = Directory(
                object_class='',
                name=self.newrdn.split('=')[1],
                parent=new_base_directory,
            )
            new_path = new_directory.create_path(new_base_directory)

        async with session.begin_nested():
            session.add_all([new_directory, new_path])
            await session.commit()

        async with session.begin_nested():
            await session.execute(
                update(Directory)
                .where(Directory.parent == directory)
                .values(parent_id=new_directory.id))

            q = update(Path)\
                .values({Path.path[directory.depth]: self.newrdn})\
                .where(Path.directories.any(id=directory.id))

            await session.execute(
                q, execution_options={"synchronize_session": 'fetch'})

            await session.commit()

        for model in DirectoryReferenceMixin.__subclasses__():
            async with session.begin_nested():
                await session.execute(
                    update(model)
                    .where(model.directory_id == directory.id)
                    .values(directory_id=new_directory.id))

        await session.refresh(directory)
        await session.delete(directory)
        await session.commit()

        yield ModifyDNResponse(result_code=LDAPCodes.SUCCESS)
