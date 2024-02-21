"""Modify protocol."""
from typing import AsyncGenerator, ClassVar

from pydantic import BaseModel
from sqlalchemy import and_, delete, or_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, Operation, Session
from ldap_protocol.ldap_responses import ModifyResponse, PartialAttribute
from ldap_protocol.utils import get_base_dn, get_groups, validate_entry
from models.ldap3 import Attribute, Directory, Group, Path, User
from security import get_password_hash

from .base import BaseRequest


class Changes(BaseModel):
    """Changes for mod request."""

    operation: Operation
    modification: PartialAttribute

    def get_name(self) -> str:
        """Get mod name."""
        return self.modification.type.lower()


class ModifyRequest(BaseRequest):
    """Modify request.

    ```
    ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        object          LDAPDN,
        changes         SEQUENCE OF change SEQUENCE {
            operation       ENUMERATED {
                add     (0),
                delete  (1),
                replace (2),
            },
            modification    PartialAttribute
        }
    }
    ```
    """

    PROTOCOL_OP: ClassVar[int] = 6

    object: str  # noqa: A003
    changes: list[Changes]

    @classmethod
    def from_data(cls, data: ASN1Row) -> 'ModifyRequest':  # noqa: D102
        entry, proto_changes = data

        changes = []
        for change in proto_changes.value:
            changes.append(Changes(
                operation=Operation(int(change.value[0].value)),
                modification=PartialAttribute(
                    type=change.value[1].value[0].value,
                    vals=[
                        attr.value for attr in change.value[1].value[1].value],
                ),
            ))
        return cls(object=entry.value, changes=changes)

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[ModifyResponse, None]:
        """Change request handler."""
        if not ldap_session.user:
            yield ModifyResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS)
            return

        base_dn = await get_base_dn(session)
        if not validate_entry(self.object.lower()):
            yield ModifyResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        obj = self.object.lower().removesuffix(
            ',' + base_dn.lower()).split(',')
        search_path = reversed(obj)

        membership1 = selectinload(Directory.user).selectinload(User.groups)
        membership2 = selectinload(Directory.group)\
            .selectinload(Group.parent_groups)

        query = select(   # noqa: ECE001
            Directory)\
            .join(Directory.path)\
            .join(Directory.attributes)\
            .join(User, isouter=True)\
            .options(
                selectinload(Directory.paths),
                membership1, membership2)\
            .filter(Path.path == search_path)

        directory = await session.scalar(query)

        if len(obj) == 0 or not directory:
            yield ModifyResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        for change in self.changes:
            try:
                if change.operation == Operation.ADD:
                    await self._add(change, directory, session, ldap_session)

                elif change.operation == Operation.DELETE:
                    await self._delete(change, directory, session)

                elif change.operation == Operation.REPLACE:
                    async with session.begin_nested():
                        await self._delete(change, directory, session, True)
                        await session.flush()
                        await self._add(
                            change, directory, session, ldap_session)

                await session.commit()
            except IntegrityError:
                await session.rollback()
                yield ModifyResponse(
                    result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
                return
            except PermissionError:
                yield ModifyResponse(
                    result_code=LDAPCodes.STRONGER_AUTH_REQUIRED)
                return

        yield ModifyResponse(result_code=LDAPCodes.SUCCESS)

    async def _delete(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
        name_only: bool = False,
    ) -> None:
        attrs = []
        name = change.modification.type.lower()

        if name == 'memberof':
            if name_only or not change.modification.vals:
                if directory.group:
                    directory.group.parent_groups.clear()

                elif directory.user:
                    directory.user.groups.clear()

            else:
                groups = await get_groups(
                    change.modification.vals, session)
                for group in groups:
                    if directory.group:
                        directory.group.parent_groups.remove(group)

                    elif directory.user:
                        directory.user.groups.remove(group)

            return

        if name_only or not change.modification.vals:
            attrs.append(Attribute.name == change.modification.type)
        else:
            for value in change.modification.vals:
                if name not in (Directory.search_fields | User.search_fields):
                    attrs.append(and_(
                        Attribute.name == change.modification.type,
                        Attribute.value == value))

        if attrs:
            del_query = delete(Attribute).filter(
                Attribute.directory == directory, or_(*attrs))

            await session.execute(del_query)

    async def _add(
        self, change: Changes,
        directory: Directory,
        session: AsyncSession,
        ldap_session: Session,
    ) -> None:
        attrs = []
        name = change.get_name()

        if name == 'memberof':
            groups = await get_groups(change.modification.vals, session)
            if directory.group:
                directory.group.parent_groups.extend(groups)

            elif directory.user:
                directory.user.groups.extend(groups)

            await session.commit()
            return

        for value in change.modification.vals:
            if name in Directory.ro_fields:
                continue

            if name in Directory.search_fields:
                await session.execute(
                    update(Directory)
                    .filter(Directory.id == directory.id)
                    .values({name: value}))

            elif name in User.search_fields and directory.user:
                await session.execute(
                    update(User)
                    .filter(User.directory == directory)
                    .values({name: value}))

            elif name in Group.search_fields and directory.group:
                await session.execute(
                    update(Group)
                    .filter(Group.directory == directory)
                    .values({name: value}))

            elif name == "userpassword" and directory.user:
                if not ldap_session.settings.USE_CORE_TLS:
                    raise PermissionError('TLS required')

                directory.user.password = get_password_hash(value)
                await session.execute(  # update bind reject attribute
                    update(Attribute)
                    .values({'value': '1'})
                    .where(
                        Attribute.directory_id == directory.user.directory_id,
                        Attribute.name == 'pwdLastSet',
                        Attribute.value == '0',
                    ))

            else:
                attrs.append(Attribute(
                    name=change.modification.type,
                    value=value,
                    directory=directory,
                ))

        session.add_all(attrs)
