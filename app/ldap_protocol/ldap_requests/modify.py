"""Modify protocol."""
from typing import AsyncGenerator, ClassVar

from pydantic import BaseModel
from sqlalchemy import and_, delete, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import joinedload, selectinload

from ldap_protocol.dialogue import LDAPCodes, Operation, Session
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    ModifyResponse,
    PartialAttribute,
)
from ldap_protocol.utils import get_base_dn, validate_entry
from models.ldap3 import Attribute, Directory, Path, User

from .base import BaseRequest


class Changes(BaseModel):
    """Changes for mod request."""

    operation: Operation
    modification: PartialAttribute


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
    def from_data(cls, data):  # noqa: D102
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
            yield ModifyResponse(**INVALID_ACCESS_RESPONSE)
            return

        base_dn = await get_base_dn(session)
        if not validate_entry(self.object.lower()):
            yield ModifyResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        obj = self.object.lower().removesuffix(
            ',' + base_dn.lower()).split(',')
        search_path = reversed(obj)

        query = select(   # noqa: ECE001
            Directory)\
            .join(Directory.path)\
            .join(Directory.attributes)\
            .join(User, isouter=True)\
            .options(
                selectinload(Directory.paths),
                joinedload(Directory.user))\
            .filter(Path.path == search_path)

        directory = await session.scalar(query)

        if len(obj) > 1 and not directory:
            yield ModifyResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        for change in self.changes:
            if change.operation == Operation.ADD:
                await self._add(change, directory, session)

            elif change.operation == Operation.DELETE:
                attrs = []
                name = change.modification.type.lower()

                for value in change.modification.vals:
                    if name not in (
                            Directory.search_fields | User.search_fields):
                        attrs.append(and_(
                            Attribute.name == change.modification.type,
                            Attribute.value == value))

                if attrs:
                    del_query = delete(Attribute).filter(
                        Attribute.directory == directory, or_(*attrs))

                    await session.execute(del_query)
                    await session.commit()

            elif change.operation == Operation.REPLACE:
                await session.delete(directory.attributes)
                await session.commit()
                await self._add(change, directory, session)

        yield ModifyResponse(result_code=LDAPCodes.SUCCESS)

    async def _add(
        self, change: Changes,
        directory: Directory,
        session: AsyncSession,
    ):
        attrs = []
        for value in change.modification.vals:
            name = change.modification.type.lower()

            if name in Directory.search_fields:
                setattr(directory, name, value)

            elif name in User.search_fields and directory.user:
                setattr(directory.user, name, value)

            else:
                attrs.append(Attribute(
                    name=change.modification.type,
                    value=value,
                    directory=directory,
                ))
        session.add_all(attrs)
        await session.commit()
