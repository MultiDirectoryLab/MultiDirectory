"""Modify DN request.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from sqlalchemy import func, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.future import select
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
    Attribute,
    Directory,
    DirectoryMembership,
    Group,
    User,
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

    async def handle(  # noqa: C901
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
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS
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

        can_delete = ctx.access_manager.check_entity_level_access(
            aces=directory.access_control_entries,
            entity_type_id=directory.entity_type_id,
        )

        if not can_delete:
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
            )

            parent_query = select(Directory).filter(
                Directory.id == directory.parent_id
            )
            parent_query = ctx.access_manager.mutate_query_with_ace_load(
                user_role_ids=ctx.ldap_session.user.role_ids,
                query=parent_query,
                ace_types=[AceType.CREATE_CHILD],
                require_attribute_type_null=True,
            )

            parent_dir = await ctx.session.scalar(parent_query)
            if parent_dir:
                can_add = ctx.access_manager.check_entity_level_access(
                    aces=parent_dir.access_control_entries,
                    entity_type_id=directory.entity_type_id,
                )
                if not can_add:
                    yield ModifyDNResponse(
                        result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS
                    )
                    return

            ctx.session.add(new_directory)
            new_directory.create_path(directory.parent, dn)
            if directory.parent:
                await ctx.role_use_case.inherit_parent_aces(
                    parent_directory=directory.parent,
                    directory=new_directory,
                )

        else:
            new_sup_query = select(Directory).filter(
                get_filter_from_path(self.new_superior)
            )
            new_sup_query = ctx.access_manager.mutate_query_with_ace_load(
                user_role_ids=ctx.ldap_session.user.role_ids,
                query=new_sup_query,
                ace_types=[AceType.CREATE_CHILD],
                require_attribute_type_null=True,
            )

            new_parent_dir = await ctx.session.scalar(new_sup_query)

            if not new_parent_dir:
                yield ModifyDNResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
                return

            can_add = ctx.access_manager.check_entity_level_access(
                aces=new_parent_dir.access_control_entries,
                entity_type_id=directory.entity_type_id,
            )

            if not can_add:
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
            )
            ctx.session.add(new_directory)
            new_directory.create_path(new_parent_dir, dn=dn)

            await ctx.role_use_case.inherit_parent_aces(
                parent_directory=new_parent_dir,
                directory=new_directory,
            )

        try:
            ctx.session.add(new_directory)
            await ctx.session.flush()
        except IntegrityError:
            await ctx.session.rollback()
            yield ModifyDNResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
            return

        async with ctx.session.begin_nested():
            await ctx.session.execute(
                update(Directory)
                .where(Directory.parent == directory)
                .values(parent_id=new_directory.id),
            )

            await ctx.session.flush()

            if self.deleteoldrdn:
                old_attr_name = directory.path[-1].split("=")[0]
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
                        directory=new_directory,
                    ),
                )
            await ctx.session.flush()

            for model in (User, Group, Attribute, DirectoryMembership):
                await ctx.session.execute(
                    update(model)
                    .where(model.directory_id == directory.id)
                    .values(directory_id=new_directory.id),
                )

            await ctx.session.flush()

            update_query = (
                update(Directory)
                .where(
                    get_path_filter(
                        directory.path,
                        column=Directory.path[1 : directory.depth],
                    ),
                )
                .values(
                    path=func.array_cat(
                        new_directory.path,
                        text("path[:depth :]").bindparams(
                            depth=directory.depth + 1,
                        ),
                    ),
                )
            )

            await ctx.session.execute(
                update_query,
                execution_options={"synchronize_session": "fetch"},
            )

            explicit_aces_query = (
                select(AccessControlEntry)
                .options(
                    selectinload(AccessControlEntry.directories),
                )
                .where(
                    AccessControlEntry.directories.any(
                        Directory.id == directory.id
                    ),
                    AccessControlEntry.depth == directory.depth,
                )
            )

            explicit_aces = (
                await ctx.session.scalars(explicit_aces_query)
            ).all()

            for ace in explicit_aces:
                ace.directories.append(new_directory)
                ace.path = new_directory.path_dn
                ace.depth = new_directory.depth

            await ctx.session.flush()

            # NOTE: update relationship, don't delete row
            await ctx.session.refresh(directory)
            await ctx.session.delete(directory)
            await ctx.session.flush()

            await ctx.session.refresh(
                instance=new_directory,
                attribute_names=["attributes"],
                with_for_update=None,
            )
            await ctx.entity_type_dao.attach_entity_type_to_directory(
                directory=new_directory,
                is_system_entity_type=False,
            )
            await ctx.session.flush()

        await ctx.session.commit()

        yield ModifyDNResponse(result_code=LDAPCodes.SUCCESS)
