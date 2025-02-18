"""Modify DN request.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from sqlalchemy import func, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    ModifyDNResponse,
)
from ldap_protocol.policies.access_policy import mutate_ap
from ldap_protocol.utils.queries import (
    get_filter_from_path,
    get_path_filter,
    validate_entry,
)
from models import Attribute, Directory, DirectoryMembership, Group, User

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

        >>> cn = main2, ou = users, dc = multifactor, dc = dev
    """

    PROTOCOL_OP: ClassVar[int] = 12

    entry: str
    newrdn: str
    deleteoldrdn: bool
    new_superior: str | None

    @classmethod
    def from_data(cls, data: list[ASN1Row]) -> "ModifyDNRequest":
        """Create structure from ASN1Row dataclass list."""
        return cls(
            entry=data[0].value,
            newrdn=data[1].value,
            deleteoldrdn=data[2].value,
            new_superior=None if len(data) < 4 else data[3].value,
        )

    async def handle(
        self, ldap_session: LDAPSession, session: AsyncSession
    ) -> AsyncGenerator[ModifyDNResponse, None]:
        """Handle message with current user."""
        if not ldap_session.user:
            yield ModifyDNResponse(**INVALID_ACCESS_RESPONSE)
            return

        if any(
            [
                not validate_entry(self.entry),
                self.new_superior and not validate_entry(self.new_superior),
                not validate_entry(self.newrdn),
            ]
        ):
            yield ModifyDNResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        query = (
            select(Directory)
            .options(
                selectinload(Directory.parent),
                selectinload(Directory.access_policies),
            )
            .filter(get_filter_from_path(self.entry))
        )

        directory = await session.scalar(mutate_ap(query, ldap_session.user))

        if not directory:
            yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        if directory.is_domain:
            yield ModifyDNResponse(result_code=LDAPCodes.UNWILLING_TO_PERFORM)
            return

        if not await session.scalar(
            mutate_ap(query, ldap_session.user, "modify")
        ):
            yield ModifyDNResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS
            )
            return

        dn, name = self.newrdn.split("=")

        if self.new_superior is None:
            new_directory = Directory(
                name=name,
                object_class=directory.object_class,
                parent_id=directory.parent_id,
                created_at=directory.created_at,
                object_guid=directory.object_guid,
                object_sid=directory.object_sid,
                access_policies=directory.access_policies,
            )
            session.add(new_directory)
            new_directory.create_path(directory.parent, dn)

        else:
            new_sup_query = (
                select(Directory)
                .options(selectinload(Directory.access_policies))
                .filter(get_filter_from_path(self.new_superior))
            )

            new_sup_query = mutate_ap(new_sup_query, ldap_session.user)

            new_parent_dir = await session.scalar(new_sup_query)

            if not new_parent_dir:
                yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
                return

            if not await session.scalar(
                mutate_ap(query, ldap_session.user, "add")
            ):
                yield ModifyDNResponse(
                    result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS
                )
                return

            new_directory = Directory(
                object_class=directory.object_class,
                name=name,
                parent=new_parent_dir,
                object_guid=directory.object_guid,
                object_sid=directory.object_sid,
                access_policies=new_parent_dir.access_policies,
            )
            session.add(new_directory)
            new_directory.create_path(new_parent_dir, dn=dn)

        try:
            session.add(new_directory)
            await session.flush()
        except IntegrityError:
            await session.rollback()
            yield ModifyDNResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
            return

        async with session.begin_nested():
            await session.execute(
                update(Directory)
                .where(Directory.parent == directory)
                .values(parent_id=new_directory.id)
            )

            await session.flush()

            if self.deleteoldrdn:
                old_attr_name = directory.path[-1].split("=")[0]
                await session.execute(
                    update(Attribute)
                    .where(
                        Attribute.directory_id == directory.id,
                        Attribute.name == old_attr_name,
                        Attribute.value == directory.name,
                    )
                    .values(name=dn, value=name)
                )
            else:
                session.add(
                    Attribute(name=dn, value=name, directory=new_directory)
                )
            await session.flush()

            for model in (User, Group, Attribute, DirectoryMembership):
                await session.execute(
                    update(model)
                    .where(model.directory_id == directory.id)
                    .values(directory_id=new_directory.id)
                )

            await session.flush()

            update_query = (
                update(Directory)
                .where(
                    get_path_filter(
                        directory.path,
                        column=Directory.path[1 : directory.depth],
                    )
                )
                .values(
                    path=func.array_cat(
                        new_directory.path,
                        #  TODO: replace text with slice
                        text("path[:depth :]").bindparams(
                            depth=directory.depth + 1
                        ),
                    )
                )
            )

            await session.execute(
                update_query,
                execution_options={"synchronize_session": "fetch"},
            )
            await session.flush()

            # NOTE: update relationship, don't delete row
            await session.refresh(directory)

            await session.delete(directory)
            await session.flush()

        await session.commit()

        yield ModifyDNResponse(result_code=LDAPCodes.SUCCESS)
