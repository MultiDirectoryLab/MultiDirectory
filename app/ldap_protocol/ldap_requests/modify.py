"""Modify protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from typing import AsyncGenerator, ClassVar

from loguru import logger
from pydantic import BaseModel
from sqlalchemy import and_, delete, or_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from config import Settings
from ldap_protocol.access_policy import mutate_ap
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, LDAPSession, Operation
from ldap_protocol.kerberos import (
    AbstractKadmin,
    KRBAPIError,
    unlock_principal,
)
from ldap_protocol.ldap_responses import ModifyResponse, PartialAttribute
from ldap_protocol.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.cte import get_members_root_group
from ldap_protocol.utils.helpers import (
    create_user_name,
    ft_to_dt,
    is_dn_in_base_directory,
)
from ldap_protocol.utils.queries import (
    get_base_directories,
    get_directories,
    get_filter_from_path,
    get_groups,
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

        query = (  # noqa: ECE001
            select(Directory)
            .join(Directory.attributes)
            .options(
                selectinload(Directory.groups),
                selectinload(Directory.group).selectinload(Group.members))
            .filter(get_filter_from_path(self.object))
        )

        directory = await session.scalar(mutate_ap(query, ldap_session.user))

        if not directory:
            yield ModifyResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        names = {change.get_name() for change in self.changes}

        password_change_requested = (
            ("userpassword" in names or 'unicodepwd' in names) and
            len(names) == 1 and
            directory.id == ldap_session.user.directory_id)

        can_modify = bool(await session.scalar(
            mutate_ap(query, ldap_session.user, 'modify')))

        if not can_modify and not password_change_requested:
            yield ModifyResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS)
            return

        for change in self.changes:
            if change.modification.type in Directory.ro_fields:
                continue

            add_args = (change, directory, session, kadmin, settings)

            try:
                if change.operation == Operation.ADD:
                    await self._add(*add_args)

                elif change.operation == Operation.DELETE:
                    await self._delete(change, directory, session)

                elif change.operation == Operation.REPLACE:
                    async with session.begin_nested():
                        await self._delete(change, directory, session, True)
                        await session.flush()
                        await self._add(*add_args)

                await session.flush()
                await session.execute(
                    update(Directory).where(Directory.id == directory.id),
                )
                await session.commit()
            except ValueError as err:
                logger.error(f"Invalid value: {err}")
                await session.rollback()
                yield ModifyResponse(
                    result_code=LDAPCodes.UNDEFINED_ATTRIBUTE_TYPE)
                return
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

            except RecursionError:
                yield ModifyResponse(
                    result_code=LDAPCodes.LOOP_DETECT)
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
            groups = await get_groups(
                    change.modification.vals, session)

            if not change.modification.vals:
                directory.groups.clear()

            elif change.operation == Operation.REPLACE:
                directory.groups = list(set(directory.groups) & set(groups))

            else:
                for group in groups:
                    directory.groups.remove(group)

            return

        if name == 'member':
            members = await get_directories(
                    change.modification.vals, session)

            if not change.modification.vals:
                directory.group.members.clear()

            elif change.operation == Operation.REPLACE:
                directory.group.members = list(set(directory.group.members) &
                                               set(members))

            else:
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

    async def _add_group_attrs(
        self, change: Changes,
        directory: Directory,
        session: AsyncSession,
    ) -> None:
        name = change.get_name()
        directories = await get_directories(change.modification.vals, session)

        if name == 'memberof':
            groups = [
                _directory.group
                for _directory in directories
                if _directory.group
            ]
            new_groups = list(set(groups) - set(directory.groups))
            directories = [new_group.directory for new_group in new_groups]
        else:
            directories = list(set(directories) - set(directory.group.members))

        if not directories:
            return

        members = await get_members_root_group(directory.path_dn, session)
        directories_to_add = [
            _directory
            for _directory in directories
            if (_directory != directory and
                _directory not in members)
        ]

        if len(directories) != len(directories_to_add):
            raise RecursionError

        if name == 'memberof':
            directory.groups.extend([
                _directory.group
                for _directory in directories
                if _directory.group])
        else:
            directory.group.members.extend(directories)

        await session.commit()

    async def _add(
        self, change: Changes,
        directory: Directory,
        session: AsyncSession,
        kadmin: AbstractKadmin,
        settings: Settings,
    ) -> None:
        attrs = []
        name = change.get_name()

        if name in {'memberof', 'member'}:
            await self._add_group_attrs(change, directory, session)
            return

        for value in change.modification.vals:
            if name == 'useraccountcontrol':
                uac_val = int(value)
                if uac_val == 0:
                    continue

                if bool(
                    uac_val & UserAccountControlFlag.ACCOUNTDISABLE,
                ) and directory.user:
                    await kadmin.lock_principal(
                        directory.user.get_upn_prefix())
                elif not bool(
                    uac_val & UserAccountControlFlag.ACCOUNTDISABLE,
                ) and directory.user:
                    await unlock_principal(
                        directory.user.user_principal_name, session)

            if name in Directory.search_fields:
                await session.execute(
                    update(Directory)
                    .filter(Directory.id == directory.id)
                    .values({name: value}))

            elif name in User.search_fields:
                if not directory.user:
                    path_dn = directory.path_dn
                    for base_directory in await get_base_directories(session):
                        if is_dn_in_base_directory(base_directory, path_dn):
                            base_dn = base_directory
                            break

                    sam_accout_name = create_user_name(directory.id)
                    user_principal_name = f"{sam_accout_name}@{base_dn.name}"
                    user = User(
                        sam_accout_name=sam_accout_name,
                        user_principal_name=user_principal_name,
                        directory=directory,
                    )
                    uac_attr = Attribute(
                        name="userAccountControl",
                        value=str(UserAccountControlFlag.NORMAL_ACCOUNT),
                        directory=directory,
                    )

                    session.add_all([user, uac_attr])
                    await session.flush()
                    await session.refresh(directory)

                if name == 'accountexpires':
                    value = ft_to_dt(int(value)) if value != '0' else None

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
                    .get_policy_settings(session, kadmin)

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
