"""Modify protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, ClassVar

from loguru import logger
from sqlalchemy import Select, and_, delete, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from config import Settings
from constants import PRIMARY_ENTITY_TYPE_NAMES
from entities import Attribute, Directory, Group, User
from enums import AceType
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.kerberos import (
    AbstractKadmin,
    KRBAPIError,
    unlock_principal,
)
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import ModifyResponse, PartialAttribute
from ldap_protocol.objects import Changes, Operation, ProtocolRequests
from ldap_protocol.policies.password import PasswordPolicyUseCases
from ldap_protocol.policies.password.dataclasses import PasswordPolicyDTO
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.cte import get_members_root_group
from ldap_protocol.utils.helpers import (
    create_user_name,
    ft_to_dt,
    is_dn_in_base_directory,
)
from ldap_protocol.utils.queries import (
    add_lock_and_expire_attributes,
    get_base_directories,
    get_directories,
    get_filter_from_path,
    get_groups,
    validate_entry,
)
from password_manager import PasswordValidator
from repo.pg.tables import directory_table, queryable_attr as qa

from .base import BaseRequest
from .contexts import LDAPModifyRequestContext


class ModifyForbiddenError(Exception):
    """Modify request is not allowed."""


MODIFY_EXCEPTION_STACK = (
    ValueError,
    IntegrityError,
    KRBAPIError,
    RecursionError,
    PermissionError,
    ModifyForbiddenError,
)

_DOMAIN_ADMIN_NAME = "domain admins"


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

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.MODIFY

    object: str
    changes: list[Changes]

    @classmethod
    def from_data(cls, data: list[ASN1Row]) -> "ModifyRequest":
        entry, proto_changes = data

        changes = []
        for change in proto_changes.value:
            changes.append(
                Changes(
                    operation=Operation(int(change.value[0].value)),
                    modification=PartialAttribute(
                        type=change.value[1].value[0].value,
                        vals=[
                            attr.value
                            for attr in change.value[1].value[1].value
                        ],
                    ),
                ),
            )
        return cls(object=entry.value, changes=changes)

    def _update_password_expiration(
        self,
        change: Changes,
        policy: PasswordPolicyDTO,
    ) -> None:
        """Update password expiration if policy allows."""
        if not (
            change.modification.type == "krbpasswordexpiration"
            and change.modification.vals[0] == "19700101000000Z"
        ):
            return

        if policy.maximum_password_age_days == 0:
            return

        now = datetime.now(timezone.utc)
        now += timedelta(days=policy.maximum_password_age_days)
        change.modification.vals[0] = now.strftime("%Y%m%d%H%M%SZ")

    async def handle(
        self,
        ctx: LDAPModifyRequestContext,
    ) -> AsyncGenerator[ModifyResponse, None]:
        """Change request handler."""
        if not ctx.ldap_session.user:
            yield ModifyResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
            return

        if not validate_entry(self.object.lower()):
            yield ModifyResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        if not ctx.ldap_session.user.role_ids:
            yield ModifyResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
            return

        policy = await ctx.password_use_cases.get_password_policy()
        query = self._get_dir_query()
        query = ctx.access_manager.mutate_query_with_ace_load(
            user_role_ids=ctx.ldap_session.user.role_ids,
            query=query,
            ace_types=[AceType.WRITE, AceType.DELETE],
            load_attribute_type=True,
        )

        directory = await ctx.session.scalar(query)

        if not directory:
            yield ModifyResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        can_modify = ctx.access_manager.check_modify_access(
            changes=self.changes,
            aces=directory.access_control_entries,
            entity_type_id=directory.entity_type_id,
        )

        names = {change.get_name() for change in self.changes}

        password_change_requested = self._check_password_change_requested(
            names,
            directory,
            ctx.ldap_session.user.directory_id,
        )

        before_attrs = self.get_directory_attrs(directory)

        try:
            if not can_modify and not password_change_requested:
                yield ModifyResponse(
                    result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
                )
                return

            for change in self.changes:
                if change.modification.l_name in Directory.ro_fields:
                    continue

                self._update_password_expiration(change, policy)

                add_args = (
                    change,
                    directory,
                    ctx.session,
                    ctx.session_storage,
                    ctx.kadmin,
                    ctx.settings,
                    ctx.ldap_session.user,
                    ctx.password_use_cases,
                    ctx.password_validator,
                )

                try:
                    if change.operation == Operation.ADD:
                        await self._add(*add_args)

                    elif change.operation == Operation.DELETE:
                        await self._delete(
                            change,
                            directory,
                            ctx.session,
                            ctx.ldap_session.user,
                        )

                    elif change.operation == Operation.REPLACE:
                        async with ctx.session.begin_nested():
                            await self._delete(
                                change,
                                directory,
                                ctx.session,
                                ctx.ldap_session.user,
                                True,
                            )
                            await ctx.session.flush()
                            await self._add(*add_args)

                    await ctx.session.flush()
                    await ctx.session.execute(
                        update(Directory).filter_by(id=directory.id),
                    )
                except MODIFY_EXCEPTION_STACK as err:
                    await ctx.session.rollback()
                    result_code, message = self._match_bad_response(err)
                    yield ModifyResponse(
                        result_code=result_code,
                        message=message,
                    )
                    return

                await ctx.session.refresh(
                    instance=directory,
                    attribute_names=["groups", "attributes", "user", "path"],
                )

            if "objectclass" in names:
                await ctx.entity_type_dao.attach_entity_type_to_directory(
                    directory=directory,
                    is_system_entity_type=False,
                )
            await ctx.session.commit()
            yield ModifyResponse(result_code=LDAPCodes.SUCCESS)
        finally:
            query = self._get_dir_query()
            directory = await ctx.session.scalar(query)
            self.set_event_data(
                {
                    "after_attrs": self.get_directory_attrs(directory),
                    "before_attrs": before_attrs,
                },
            )

    def _match_bad_response(self, err: BaseException) -> tuple[LDAPCodes, str]:
        match err:
            case ValueError():
                logger.error(f"Invalid value: {err}")
                return LDAPCodes.UNDEFINED_ATTRIBUTE_TYPE, ""

            case IntegrityError():
                return LDAPCodes.ENTRY_ALREADY_EXISTS, ""

            case KRBAPIError():
                return LDAPCodes.UNAVAILABLE, "Kerberos error"

            case RecursionError():
                return LDAPCodes.LOOP_DETECT, ""

            case PermissionError():
                return LDAPCodes.STRONGER_AUTH_REQUIRED, ""

            case ModifyForbiddenError():
                return LDAPCodes.OPERATIONS_ERROR, str(err)

            case _:
                raise err

    def _get_dir_query(self) -> Select:
        return (
            select(Directory)
            .options(joinedload(qa(Directory.user)))
            .options(selectinload(qa(Directory.attributes)))
            .options(joinedload(qa(Directory.entity_type)))
            .options(
                selectinload(qa(Directory.groups)).selectinload(
                    qa(Group.directory),
                ),
                selectinload(qa(Directory.groups)).selectinload(
                    qa(Group.members),
                ),
                joinedload(qa(Directory.group)).selectinload(
                    qa(Group.members),
                ),
            )
            .filter(get_filter_from_path(self.object))
        )

    def _check_password_change_requested(
        self,
        names: set[str],
        directory: Directory,
        user_dir_id: int,
    ) -> bool:
        return (
            ("userpassword" in names or "unicodepwd" in names)
            and len(names) == 1
            and directory.id == user_dir_id
        )

    async def _can_delete_group_from_directory(
        self,
        directory: Directory,
        user: UserSchema,
        groups: list[Group],
        operation: Operation,
    ) -> None:
        """Check if the request can delete group from directory."""
        if operation == Operation.REPLACE:
            for group in directory.groups:
                if (
                    group.directory.name == _DOMAIN_ADMIN_NAME
                    and directory.path_dn == user.dn
                    and group not in groups
                ):
                    raise ModifyForbiddenError(
                        "Can't delete yourself from group.",
                    )

        elif operation == Operation.DELETE:
            for group in groups:
                if (
                    group.directory.name == _DOMAIN_ADMIN_NAME
                    and directory.path_dn == user.dn
                ):
                    raise ModifyForbiddenError(
                        "Can't delete yourself from group.",
                    )

    async def _can_delete_member_from_directory(
        self,
        directory: Directory,
        user: UserSchema,
        members: list[Directory],
        operation: Operation,
    ) -> None:
        """Check if the request can delete directory member."""
        modified_members_dns = {member.path_dn for member in members}
        is_user_not_in_replaced = (
            operation == Operation.REPLACE
            and user.dn not in modified_members_dns
        )
        is_user_in_deleted = (
            operation == Operation.DELETE and user.dn in modified_members_dns
        )

        if directory.name == _DOMAIN_ADMIN_NAME and (
            is_user_in_deleted or is_user_not_in_replaced
        ):
            raise ModifyForbiddenError("Can't delete yourself from group.")

    async def _delete_memberof(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
        user: UserSchema,
    ) -> None:
        """Delete memberOf attribute from group."""
        groups = await get_groups(change.modification.vals, session)  # type: ignore
        await self._can_delete_group_from_directory(
            directory=directory,
            user=user,
            groups=groups,
            operation=change.operation,
        )

        if not change.modification.vals:
            directory.groups.clear()

        elif change.operation == Operation.REPLACE:
            directory.groups = [
                g
                for g in directory.groups
                if g.id in map(lambda g: g.id, groups)
            ]

        else:
            for group in groups:
                directory.groups.remove(group)

    async def _delete_member(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
        user: UserSchema,
    ) -> None:
        """Delete member attribute from group."""
        members = await get_directories(change.modification.vals, session)  # type: ignore
        await self._can_delete_member_from_directory(
            directory=directory,
            user=user,
            members=members,
            operation=change.operation,
        )

        if not change.modification.vals:
            directory.group.members.clear()

        elif change.operation == Operation.REPLACE:
            directory.group.members = [
                member
                for member in directory.group.members
                if member in members
            ]

        else:
            for member in members:
                directory.group.members.remove(member)

    async def _validate_object_class_modification(
        self,
        change: Changes,
        directory: Directory,
    ) -> None:
        if not (
            directory.entity_type
            and directory.entity_type.name in PRIMARY_ENTITY_TYPE_NAMES
        ):
            return

        required_obj_classes = directory.entity_type.object_class_names_set
        is_object_class_in_replaced = (
            change.operation == Operation.REPLACE
            and required_obj_classes
            and not required_obj_classes.issubset(change.modification.vals)
        )
        is_object_class_in_deleted = (
            change.operation == Operation.DELETE
            and required_obj_classes
            and required_obj_classes & set(change.modification.vals)
        )

        if is_object_class_in_replaced or is_object_class_in_deleted:
            raise ModifyForbiddenError("ObjectClass can't be deleted.")

    async def _delete(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
        user: UserSchema,
        name_only: bool = False,
    ) -> None:
        attrs = []
        name = change.modification.type.lower()

        if name == "memberof":
            await self._delete_memberof(
                change=change,
                directory=directory,
                session=session,
                user=user,
            )
            return

        if name == "member":
            await self._delete_member(
                change=change,
                directory=directory,
                session=session,
                user=user,
            )
            return

        if name == "objectclass":
            await self._validate_object_class_modification(change, directory)

        if name_only or not change.modification.vals:
            attrs.append(qa(Attribute.name) == change.modification.type)
        else:
            for value in change.modification.vals:
                if name not in (Directory.search_fields | User.search_fields):
                    if isinstance(value, str):
                        condition = qa(Attribute.value) == value
                    elif isinstance(value, bytes):
                        condition = qa(Attribute.bvalue) == value

                    attrs.append(
                        and_(
                            qa(Attribute.name) == change.modification.type,
                            condition,
                        ),
                    )

        if attrs:
            del_query = (
                delete(Attribute)
                .filter_by(directory=directory)
                .filter(or_(*attrs))
            )  # fmt: skip

            await session.execute(del_query)

    async def _add_group_attrs(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
    ) -> None:
        name = change.get_name()
        directories = await get_directories(change.modification.vals, session)  # type: ignore

        if name == "memberof":
            groups = [
                _directory.group
                for _directory in directories
                if _directory.group
            ]
            new_groups = [g for g in groups if g not in directory.groups]
            directories = [new_group.directory for new_group in new_groups]
        else:
            directories = [
                d
                for d in directories
                if not directory.group or d not in directory.group.members
            ]

        if not directories:
            return

        members = await get_members_root_group(directory.path_dn, session)
        directories_to_add = [
            _directory
            for _directory in directories
            if (_directory != directory and _directory not in members)
        ]

        if len(directories) != len(directories_to_add):
            raise RecursionError

        if name == "memberof":
            directory.groups.extend(
                [
                    _directory.group
                    for _directory in directories
                    if _directory.group
                ],
            )
        else:
            directory.group.members.extend(directories)

        await session.commit()

    async def _add(  # noqa: C901
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
        session_storage: SessionStorage,
        kadmin: AbstractKadmin,
        settings: Settings,
        current_user: UserSchema,
        password_use_cases: PasswordPolicyUseCases,
        password_validator: PasswordValidator,
    ) -> None:
        attrs = []
        name = change.get_name()

        if name in {"memberof", "member"}:
            await self._add_group_attrs(change, directory, session)
            return

        for value in change.modification.vals:
            if name == "useraccountcontrol":
                uac_val = int(value)

                if not UserAccountControlFlag.is_value_valid(uac_val):
                    continue

                elif (
                    bool(
                        uac_val & UserAccountControlFlag.ACCOUNTDISABLE,
                    )
                    and directory.user
                ):
                    if directory.path_dn == current_user.dn:
                        raise ModifyForbiddenError(
                            "Can't swith off own account.",
                        )

                    await kadmin.lock_principal(
                        directory.user.get_upn_prefix(),
                    )

                    await add_lock_and_expire_attributes(
                        session,
                        directory,
                        settings.TIMEZONE,
                    )

                    await session_storage.clear_user_sessions(
                        directory.user.id,
                    )

                elif (
                    not bool(
                        uac_val & UserAccountControlFlag.ACCOUNTDISABLE,
                    )
                    and directory.user
                ):
                    await unlock_principal(
                        directory.user.user_principal_name,
                        session,
                    )

                    await session.execute(
                        delete(Attribute)
                        .filter_by(
                            name="nsAccountLock",
                            directory=directory,
                        ),
                    )  # fmt: skip

                    await session.execute(
                        delete(Attribute)
                        .filter_by(
                            name="shadowExpire",
                            directory=directory,
                        ),
                    )  # fmt: skip

            if name == "pwdlastset" and value == "0" and directory.user:
                await kadmin.force_princ_pw_change(
                    directory.user.get_upn_prefix(),
                )

            if name == directory.rdname:
                await session.execute(
                    update(Directory)
                    .filter(directory_table.c.id == directory.id)
                    .values(name=value),
                )

            if name in Directory.search_fields:
                await session.execute(
                    update(Directory)
                    .filter(directory_table.c.id == directory.id)
                    .values({name: value}),
                )

            elif name in User.search_fields:
                if not directory.user:
                    path_dn = directory.path_dn
                    for base_directory in await get_base_directories(session):
                        if is_dn_in_base_directory(base_directory, path_dn):
                            base_dn = base_directory
                            break

                    sam_account_name = create_user_name(directory.id)
                    user_principal_name = f"{sam_account_name}@{base_dn.name}"
                    user = User(
                        sam_account_name=sam_account_name,
                        user_principal_name=user_principal_name,
                        directory_id=directory.id,
                    )
                    uac_attr = Attribute(
                        name="userAccountControl",
                        value=str(UserAccountControlFlag.NORMAL_ACCOUNT),
                        directory_id=directory.id,
                    )

                    session.add_all([user, uac_attr])
                    await session.flush()
                    await session.refresh(directory)

                if name == "accountexpires":
                    new_value = ft_to_dt(int(value)) if value != "0" else None
                else:
                    new_value = value  # type: ignore

                await session.execute(
                    update(User)
                    .filter_by(directory=directory)
                    .values({name: new_value}),
                )

            elif name in Group.search_fields and directory.group:
                await session.execute(
                    update(Group)
                    .filter_by(directory=directory)
                    .values({name: value}),
                )

            elif name in ("userpassword", "unicodepwd") and directory.user:
                if not settings.USE_CORE_TLS:
                    raise PermissionError("TLS required")

                if isinstance(value, bytes):
                    raise ValueError("password is bytes")

                try:
                    value = value.replace("\\x00", "\x00")
                    value = value.encode().decode("UTF-16LE")[1:-1]
                except UnicodeDecodeError:
                    pass

                errors = await password_use_cases.check_password_violations(
                    password=value,
                    user=directory.user,
                )

                if errors:
                    raise PermissionError(
                        f"Password policy violation: {errors}",
                    )

                directory.user.password = password_validator.get_password_hash(
                    value,
                )
                await password_use_cases.post_save_password_actions(
                    directory.user,
                )
                await kadmin.create_or_update_principal_pw(
                    directory.user.get_upn_prefix(),
                    value,
                )

            else:
                attrs.append(
                    Attribute(
                        name=change.modification.type,
                        value=value if isinstance(value, str) else None,
                        bvalue=value if isinstance(value, bytes) else None,
                        directory_id=directory.id,
                    ),
                )

        session.add_all(attrs)
