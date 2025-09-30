"""Modify DN request.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from enums import AceType
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    ModifyDNResponse,
)
from ldap_protocol.objects import ProtocolRequests
from ldap_protocol.utils.queries import (
    get_filter_from_path,
    get_path_filter,
    validate_entry,
)
from models import (
    AccessControlEntry,
    AccessControlEntryDirectoryMembership,
    Attribute,
    Directory,
)

from .base import BaseRequest
from .contexts import LDAPModifyDNRequestContext


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

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.MODIFY_DN

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
        self,
        ctx: LDAPModifyDNRequestContext,
    ) -> AsyncGenerator[ModifyDNResponse, None]:
        """Handle message with current user."""
        if not ctx.ldap_session.user:
            yield ModifyDNResponse(**INVALID_ACCESS_RESPONSE)
            return

        if any(
            [
                not validate_entry(self.entry),
                self.new_superior and not validate_entry(self.new_superior),
                not validate_entry(self.newrdn),
            ],
        ):
            yield ModifyDNResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        if not ctx.ldap_session.user.role_ids:
            yield ModifyDNResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
            return

        query = (
            select(Directory)
            .options(
                selectinload(Directory.parent),
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
            yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        if directory.is_domain:
            yield ModifyDNResponse(result_code=LDAPCodes.UNWILLING_TO_PERFORM)
            return

        dn, name = self.newrdn.split("=")

        directory.name = name

        old_path = directory.path
        old_depth = directory.depth

        if (
            self.new_superior
            and directory.parent
            and self.new_superior != directory.parent.path_dn
        ):
            new_sup_query = select(Directory).filter(
                get_filter_from_path(self.new_superior),
            )
            new_sup_query = ctx.access_manager.mutate_query_with_ace_load(
                user_role_ids=ctx.ldap_session.user.role_ids,
                query=new_sup_query,
                ace_types=[AceType.CREATE_CHILD],
                require_attribute_type_null=True,
            )

            parent_dir = await ctx.session.scalar(new_sup_query)

            if not parent_dir:
                yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
                return

            can_add = ctx.access_manager.check_entity_level_access(
                aces=parent_dir.access_control_entries,
                entity_type_id=directory.entity_type_id,
            )

            if not can_add:
                yield ModifyDNResponse(
                    result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
                )
                return

            directory.parent = parent_dir
            directory.create_path(parent_dir, dn=dn)

            try:
                await ctx.session.flush()
                await ctx.session.execute(
                    delete(AccessControlEntryDirectoryMembership)
                    .filter_by(directory_id=directory.id),
                )  # fmt: skip

                await ctx.role_use_case.inherit_parent_aces(
                    parent_directory=parent_dir,
                    directory=directory,
                )
                await ctx.session.flush()
            except IntegrityError:
                await ctx.session.rollback()
                yield ModifyDNResponse(
                    result_code=LDAPCodes.ENTRY_ALREADY_EXISTS,
                )
                return

        async with ctx.session.begin_nested():
            if self.deleteoldrdn:
                old_attr_name = old_path[-1].split("=")[0]
                await ctx.session.execute(
                    update(Attribute)
                    .where(
                        Attribute.directory_id == directory.id,
                        Attribute.name == old_attr_name,
                        Attribute.value == directory.name,
                    )
                    .values(name=dn, value=name),
                )
            else:
                ctx.session.add(
                    Attribute(
                        name=dn,
                        value=name,
                        directory=directory,
                    ),
                )
            await ctx.session.flush()

            new_path = directory.path[:-1] + [f"{dn}={name}"]
            if old_path != new_path:
                update_query = (
                    update(Directory)
                    .where(
                        get_path_filter(
                            old_path,
                            column=Directory.path[1:old_depth],
                        ),
                    )
                    .values(
                        path=func.array_cat(
                            new_path,
                            text("path[:depth :]").bindparams(
                                depth=old_depth + 1,
                            ),
                        ),
                    )
                )
                await ctx.session.execute(
                    update_query,
                    execution_options={"synchronize_session": "fetch"},
                )
                await ctx.session.flush()

                await ctx.session.refresh(
                    directory,
                    attribute_names=["path", "depth"],
                )
                child_dir_query = select(Directory).where(
                    Directory.id != directory.id,
                    get_path_filter(
                        directory.path,
                        column=Directory.path[1 : directory.depth],
                    ),
                )
                child_dirs = (await ctx.session.scalars(child_dir_query)).all()
                for child_dir in child_dirs:
                    child_dir.depth += len(new_path) - len(old_path)
                    await ctx.session.flush()

                explicit_aces_query = (
                    select(AccessControlEntry)
                    .options(
                        selectinload(AccessControlEntry.directories),
                    )
                    .where(
                        AccessControlEntry.directories.any(
                            Directory.id == directory.id,
                        ),
                        AccessControlEntry.depth == old_depth,
                    )
                )
                explicit_aces = (
                    await ctx.session.scalars(explicit_aces_query)
                ).all()
                for ace in explicit_aces:
                    ace.directories.append(directory)
                    ace.path = directory.path_dn
                    ace.depth = directory.depth

            await ctx.session.flush()

        await ctx.session.commit()

        yield ModifyDNResponse(result_code=LDAPCodes.SUCCESS)
