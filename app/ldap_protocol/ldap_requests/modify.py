"""Modify protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from typing import AsyncGenerator, ClassVar

from pydantic import BaseModel
from sqlalchemy import and_, delete, or_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from config import Settings
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, LDAPSession, Operation
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_responses import ModifyResponse, PartialAttribute
from ldap_protocol.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.utils import (
    ft_to_dt,
    get_directories,
    get_groups,
    get_path_filter,
    get_search_path,
    validate_entry,
)
from models.ldap3 import Attribute, Directory, Group, User
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

    async def handle(
        self, ldap_session: LDAPSession,
        session: AsyncSession,
        kadmin: AbstractKadmin,
        settings: Settings,
    ) -> AsyncGenerator[ModifyResponse, None]:
        """Change request handler."""
        if not ldap_session.user:
            yield ModifyResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS)
            return

        if not validate_entry(self.object.lower()):
            yield ModifyResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        search_path = get_search_path(self.object)

        membership1 = selectinload(Directory.user).selectinload(User.groups)
        membership2 = selectinload(Directory.group)\
            .selectinload(Group.parent_groups)
        membership3 = selectinload(Directory.group)\
            .selectinload(Group.members)

        query = select(   # noqa: ECE001
            Directory)\
            .join(Directory.path)\
            .join(Directory.attributes)\
            .join(User, isouter=True)\
            .options(
                selectinload(Directory.paths),
                membership1, membership2, membership3)\
            .filter(get_path_filter(search_path))

        directory = await session.scalar(query)

        if len(search_path) == 0 or not directory:
            yield ModifyResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        for change in self.changes:
            if change.modification.type in Directory.ro_fields:
                continue

            try:
                if change.operation == Operation.ADD:
                    await self._add(
                        change, directory, session, kadmin, settings)

                elif change.operation == Operation.DELETE:
                    await self._delete(change, directory, session)

                elif change.operation == Operation.REPLACE:
                    async with session.begin_nested():
                        await self._delete(change, directory, session, True)
                        await session.flush()
                        await self._add(
                            change, directory, session, kadmin, settings)

                await session.execute(
                    update(Directory).where(Directory.id == directory.id),
                )
                await session.commit()
            except IntegrityError:
                await session.rollback()
                yield ModifyResponse(
                    result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
                return

            except KRBAPIError:
                await session.rollback()
                yield ModifyResponse(
                    result_code=LDAPCodes.UNAVAILABLE,
                    errorMessage="Kerberos error")
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

        if name == 'member':
            if name_only or not change.modification.vals:
                directory.group.members.clear()
            else:
                members = await get_directories(
                    change.modification.vals, session)
                for member in members:
                    directory.group.members.remove(member)
            return

        if name_only or not change.modification.vals:
            attrs.append(Attribute.name == change.modification.type)
        else:
            for value in change.modification.vals:
                if name not in (Directory.search_fields | User.search_fields):
                    if isinstance(value, str):
                        condition = Attribute.value == value
                    elif isinstance(value, bytes):
                        condition = Attribute.bvalue == value
                    else:
                        continue

                    attrs.append(and_(
                        Attribute.name == change.modification.type,
                        condition))

        if attrs:
            del_query = delete(Attribute).filter(
                Attribute.directory == directory, or_(*attrs))

            await session.execute(del_query)

    async def _add(
        self, change: Changes,
        directory: Directory,
        session: AsyncSession,
        kadmin: AbstractKadmin,
        settings: Settings,
    ) -> None:
        attrs = []
        name = change.get_name()

        if name == 'memberof':
            directory.groups.extend(
                await get_groups(change.modification.vals, session))

            await session.commit()
            return
        if name == 'member':
            directory.group.members.extend(
                await get_directories(change.modification.vals, session))
            await session.commit()
            return

        for value in change.modification.vals:
            if name in Directory.search_fields:
                await session.execute(
                    update(Directory)
                    .filter(Directory.id == directory.id)
                    .values({name: value}))

            elif name in User.search_fields and directory.user:
                if name == 'accountexpires':
                    value = ft_to_dt(int(value))

                await session.execute(
                    update(User)
                    .filter(User.directory == directory)
                    .values({name: value}))

            elif name in Group.search_fields and directory.group:
                await session.execute(
                    update(Group)
                    .filter(Group.directory == directory)
                    .values({name: value}))

            elif name in ("userpassword", 'unicodepwd') and directory.user:
                if not settings.USE_CORE_TLS:
                    raise PermissionError('TLS required')

                try:
                    value = value.replace('\\x00', '\x00')
                    value = value.encode().decode("UTF-16LE")[1:-1]
                except UnicodeDecodeError:
                    pass

                validator = await PasswordPolicySchema\
                    .get_policy_settings(session)

                p_last_set = await validator.get_pwd_last_set(
                    session, directory.id)

                errors = await validator.validate_password_with_policy(
                    value, directory.user)

                if validator.validate_min_age(p_last_set):
                    errors.append("Minimum age violation")

                if errors:
                    raise PermissionError(
                        f'Password policy violation: {errors}')

                directory.user.password = get_password_hash(value)
                await post_save_password_actions(directory.user, session)
                await kadmin.create_or_update_principal_pw(
                    directory.user.get_upn_prefix(), value)

            else:
                attrs.append(Attribute(
                    name=change.modification.type,
                    value=value if isinstance(value, str) else None,
                    bvalue=value if isinstance(value, bytes) else None,
                    directory=directory,
                ))

        session.add_all(attrs)
