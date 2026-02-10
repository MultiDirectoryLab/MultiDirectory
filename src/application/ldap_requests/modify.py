"""Modify protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, ClassVar

from loguru import logger
from pydantic import PrivateAttr
from sqlalchemy import Select, and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from application.asn1parser import ASN1Row
from application.dialogue import UserSchema
from application.kerberos import AbstractKadmin, unlock_principal
from application.kerberos.exceptions import (
    KRBAPIConnectionError,
    KRBAPIForcePasswordChangeError,
    KRBAPILockPrincipalError,
    KRBAPIPrincipalNotFoundError,
    KRBAPIRenamePrincipalError,
)
from application.ldap_codes import LDAPCodes
from application.ldap_responses import ModifyResponse, PartialAttribute
from application.objects import (
    Changes,
    Operation,
    ProtocolRequests,
    UserAccountControlFlag,
)
from application.policies.password import PasswordPolicyUseCases
from application.session_storage import SessionStorage
from application.utils.cte import check_root_group_membership_intersection
from application.utils.helpers import (
    ft_to_dt,
    is_dn_in_base_directory,
    validate_entry,
)
from application.utils.queries import (
    add_lock_and_expire_attributes,
    clear_group_membership,
    extend_group_membership,
    get_base_directories,
    get_directories,
    get_directory_by_rid,
    get_filter_from_path,
    get_groups,
    remove_disallowed_group_members,
    remove_from_group_membership,
)
from config import Settings
from constants import DOMAIN_ADMIN_GROUP_NAME
from domain.entities import Attribute, Directory, Group, User
from enums import AceType, EntityTypeNames
from infrastructure.pg.tables import (
    directory_memberships_table,
    directory_table,
    queryable_attr as qa,
)
from password_utils import PasswordUtils

from .base import BaseRequest
from .contexts import LDAPModifyRequestContext


class ModifyForbiddenError(Exception):
    """Modify request is not allowed."""


MODIFY_EXCEPTION_STACK = (
    ValueError,
    IntegrityError,
    RecursionError,
    PermissionError,
    ModifyForbiddenError,
    KRBAPIPrincipalNotFoundError,
    KRBAPIRenamePrincipalError,
    KRBAPILockPrincipalError,
    KRBAPIForcePasswordChangeError,
)


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

    RESPONSE_TYPE: ClassVar[type] = ModifyResponse
    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.MODIFY
    CONTEXT_TYPE: ClassVar[type] = LDAPModifyRequestContext

    object: str
    changes: list[Changes]

    # NOTE: If the old value was changed (for example, in _delete)
    # in one method, then you need to have access to the old value
    # from other methods (for example, from _add)
    _old_vals: dict[str, str | None] = PrivateAttr(default_factory=dict)

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

    async def _update_password_expiration(
        self,
        change: Changes,
        user: User | None,
        password_use_cases: PasswordPolicyUseCases,
    ) -> None:
        """Update password expiration if policy allows."""
        if not user:
            return

        if not (
            change.l_type == "krbpasswordexpiration"
            and change.modification.vals[0] == "19700101000000Z"
        ):
            return

        max_age_days = await password_use_cases.get_max_age_days_for_user(user)
        if max_age_days == 0:
            return

        now = datetime.now(timezone.utc) + timedelta(days=max_age_days)
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

        names = {change.l_type for change in self.changes}

        password_change_requested = self._is_password_change_requested(names)
        self_modify = directory.id == ctx.ldap_session.user.directory_id

        if (
            password_change_requested
            and await ctx.password_use_cases.is_password_change_restricted(
                directory.id,
            )
        ):
            yield ModifyResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
            return

        before_attrs = self.get_directory_attrs(directory)
        entity_type = directory.entity_type
        try:
            if not can_modify and not (
                password_change_requested and self_modify
            ):
                yield ModifyResponse(
                    result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
                )
                return

            for change in self.changes:
                if change.l_type in Directory.ro_fields:
                    continue

                if not ctx.attribute_value_validator.is_partial_attribute_valid(  # noqa: E501
                    entity_type.name if entity_type else "",
                    change.modification,
                ):
                    await ctx.session.rollback()
                    yield ModifyResponse(
                        result_code=LDAPCodes.UNDEFINED_ATTRIBUTE_TYPE,
                        error_message="Invalid attribute value(s)",
                    )
                    return

                await self._update_password_expiration(
                    change,
                    directory.user,
                    ctx.password_use_cases,
                )

                add_args = (
                    change,
                    directory,
                    ctx.session,
                    ctx.session_storage,
                    ctx.kadmin,
                    ctx.settings,
                    ctx.ldap_session.user,
                    ctx.password_use_cases,
                    ctx.password_utils,
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

                except MODIFY_EXCEPTION_STACK as err:
                    await ctx.session.rollback()
                    result_code, error_message = self._match_bad_response(err)
                    yield ModifyResponse(
                        result_code=result_code,
                        error_message=error_message,
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

            case RecursionError():
                return LDAPCodes.LOOP_DETECT, ""

            case PermissionError():
                return LDAPCodes.STRONGER_AUTH_REQUIRED, ""

            case ModifyForbiddenError():
                return LDAPCodes.OPERATIONS_ERROR, str(err)

            case KRBAPIRenamePrincipalError():
                return LDAPCodes.UNAVAILABLE, "Kerberos error"

            case KRBAPIPrincipalNotFoundError():
                return LDAPCodes.UNAVAILABLE, "Kerberos error"

            case KRBAPIConnectionError():
                return LDAPCodes.UNAVAILABLE, "Kerberos error"

            case KRBAPILockPrincipalError():
                return LDAPCodes.UNAVAILABLE, "Kerberos error"

            case KRBAPIForcePasswordChangeError():
                return LDAPCodes.UNAVAILABLE, "Kerberos error"

            case _:
                raise err

    def _get_dir_query(self) -> Select[tuple[Directory]]:
        return (
            select(Directory)
            .options(joinedload(qa(Directory.user)))
            .options(selectinload(qa(Directory.attributes)))
            .options(joinedload(qa(Directory.entity_type)))
            .options(
                selectinload(qa(Directory.groups)).joinedload(
                    qa(Group.directory),
                ),
                joinedload(qa(Directory.group)).selectinload(
                    qa(Group.members),
                ),
            )
            .filter(get_filter_from_path(self.object))
        )

    def _is_password_change_requested(
        self,
        names: set[str],
    ) -> bool:
        return bool(names & {"userpassword", "unicodepwd"})

    def _get_primary_group_id(self, directory: Directory) -> str | None:
        return next(
            (
                attr.value
                for attr in directory.attributes
                if attr.name == "primaryGroupID"
            ),
            None,
        )

    def _contain_primary_group(
        self,
        groups: list[Group],
        primary_group_id: str,
    ) -> bool:
        return any(
            group.directory.relative_id == primary_group_id for group in groups
        )

    async def _get_directories_with_primary_group_id(
        self,
        primary_group_id: str,
        session: AsyncSession,
        directory_ids: list[int],
    ) -> list[Directory]:
        query = (
            select(Directory)
            .join(Attribute)
            .where(
                qa(Directory.id).in_(directory_ids),
                qa(Attribute.name) == "primaryGroupID",
                qa(Attribute.value) == primary_group_id,
            )
        )
        return list(await session.scalars(query))

    async def _get_members_with_primary_group_id(
        self,
        primary_group_id: str,
        group: Group,
        session: AsyncSession,
    ) -> list[Directory]:
        query = (
            select(Directory)
            .join(
                directory_memberships_table,
                directory_memberships_table.c.directory_id == Directory.id,
            )
            .join(Attribute)
            .where(
                directory_memberships_table.c.group_id == group.id,
                qa(Attribute.name) == "primaryGroupID",
                qa(Attribute.value) == primary_group_id,
            )
        )
        return list(await session.scalars(query))

    def _is_primary_group_deleted(
        self,
        groups: list[Group],
        primary_group_id: str,
        operation: Operation,
    ) -> bool:
        if operation == Operation.REPLACE:
            return not self._contain_primary_group(groups, primary_group_id)
        elif operation == Operation.DELETE:
            return self._contain_primary_group(groups, primary_group_id)
        return False

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
                    group.directory.name == DOMAIN_ADMIN_GROUP_NAME
                    and directory.path_dn == user.dn
                    and group not in groups
                ):
                    raise ModifyForbiddenError(
                        "Can't delete yourself from group.",
                    )

        elif operation == Operation.DELETE:
            for group in groups:
                if (
                    group.directory.name == DOMAIN_ADMIN_GROUP_NAME
                    and directory.path_dn == user.dn
                ):
                    raise ModifyForbiddenError(
                        "Can't delete yourself from group.",
                    )

        primary_group_id = self._get_primary_group_id(directory)
        if not primary_group_id:
            return

        if self._is_primary_group_deleted(groups, primary_group_id, operation):
            raise ModifyForbiddenError(
                "Can't delete primary group from user.",
            )

    async def _can_delete_member_from_directory(
        self,
        directory: Directory,
        user: UserSchema,
        members: list[Directory],
        operation: Operation,
        session: AsyncSession,
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

        if directory.name == DOMAIN_ADMIN_GROUP_NAME and (
            is_user_in_deleted or is_user_not_in_replaced
        ):
            raise ModifyForbiddenError("Can't delete yourself from group.")

        if operation == Operation.DELETE:
            members_with_primary_group = (
                await self._get_directories_with_primary_group_id(
                    directory.relative_id,
                    session,
                    [m.id for m in members],
                )
            )

            if members_with_primary_group:
                raise ModifyForbiddenError(
                    "Can't delete member with primary group id same as group.",
                )

        if operation == Operation.REPLACE:
            members_with_primary_group = (
                await self._get_members_with_primary_group_id(
                    directory.relative_id,
                    directory.group,
                    session,
                )
            )

            new_members_ids = {m.id for m in members}

            if any(
                member.id not in new_members_ids
                for member in members_with_primary_group
            ):
                raise ModifyForbiddenError(
                    "Can't delete member with primary group.",
                )

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
            session=session,
        )

        if not change.modification.vals:
            await clear_group_membership(directory.group, session)

        elif change.operation == Operation.REPLACE:
            await remove_disallowed_group_members(
                directory.group,
                members,
                session,
            )

        else:
            await remove_from_group_membership(
                directory.group,
                members,
                session,
            )

    async def _validate_object_class_modification(
        self,
        change: Changes,
        directory: Directory,
    ) -> None:
        if not (
            directory.entity_type
            and directory.entity_type.name in EntityTypeNames
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

    def _need_to_cache_samaccountname_old_value(
        self,
        change: Changes,
        directory: Directory,
    ) -> bool:
        return bool(
            directory.entity_type
            and directory.entity_type.name == EntityTypeNames.COMPUTER
            and change.l_type == "samaccountname"
            and not self._old_vals.get(change.modification.type),
        )

    async def _delete(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
        user: UserSchema,
        name_only: bool = False,
    ) -> None:
        attrs = []

        if change.l_type == "memberof":
            await self._delete_memberof(
                change=change,
                directory=directory,
                session=session,
                user=user,
            )
            return

        if change.l_type == "member":
            await self._delete_member(
                change=change,
                directory=directory,
                session=session,
                user=user,
            )
            return

        if change.l_type == "objectclass":
            await self._validate_object_class_modification(change, directory)

        if name_only or not change.modification.vals:
            attrs.append(qa(Attribute.name) == change.modification.type)
        else:
            for value in change.modification.vals:
                if change.l_type not in (
                    Directory.search_fields | User.search_fields
                ):
                    if isinstance(value, str):
                        condition = qa(Attribute.value) == value
                    elif isinstance(value, bytes):
                        condition = qa(Attribute.bvalue) == value

                    attrs.append(
                        and_(
                            func.lower(qa(Attribute.name)) == change.l_type,
                            condition,
                        ),
                    )  # fmt: skip

        if self._need_to_cache_samaccountname_old_value(change, directory):
            vals = directory.attributes_dict.get(change.modification.type)
            if vals:
                self._old_vals[change.modification.type] = vals[0]

        if attrs:
            del_query = (
                delete(Attribute)
                .filter_by(directory=directory)
                .filter(or_(*attrs))
            )  # fmt: skip

            await session.execute(del_query)

    async def _add_primary_group_attribute(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
    ) -> None:
        if not change.modification.vals:
            return

        rid = str(change.modification.vals[0])

        if self._contain_primary_group(directory.groups, rid):
            session.add(
                Attribute(
                    name="primaryGroupID",
                    value=rid,
                    directory_id=directory.id,
                ),
            )
            await session.commit()
            return

        rid_dir = await get_directory_by_rid(rid, session)

        if not rid_dir or not rid_dir.group:
            raise ModifyForbiddenError("Group with such RID not found.")

        directory.groups.append(rid_dir.group)
        session.add(
            Attribute(
                name="primaryGroupID",
                value=str(rid_dir.relative_id),
                directory_id=directory.id,
            ),
        )
        await session.commit()

    async def _add_memberof(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
    ) -> None:
        """Add memberOf attribute to user or computer."""
        directories = await get_directories(change.modification.vals, session)  # type: ignore

        groups = [
            _directory.group for _directory in directories if _directory.group
        ]
        new_groups = [g for g in groups if g not in directory.groups]
        directories = [new_group.directory for new_group in new_groups]

        if not directories:
            return

        if directory.group and await check_root_group_membership_intersection(
            directory.path_dn,
            session,
            [d.id for d in directories],
        ):
            raise RecursionError

        directory.groups.extend(
            [_directory.group for _directory in directories],
        )
        await session.flush()

    async def _add_member(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
    ) -> None:
        """Add member attribute to group."""
        directories = await get_directories(
            change.modification.vals,  # type: ignore
            session,
            excluded_group=directory.group,
        )

        if not directories:
            return

        group_directories = [d for d in directories if d.group]
        if (
            group_directories
            and await check_root_group_membership_intersection(
                directory.path_dn,
                session,
                [d.id for d in group_directories],
            )
        ):
            raise RecursionError

        await extend_group_membership(directory.group, directories, session)
        await session.flush()

    async def _add_group_attrs(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
    ) -> None:
        if change.l_type == "primarygroupid":
            await self._add_primary_group_attribute(
                change,
                directory,
                session,
            )
        elif change.l_type == "memberof":
            await self._add_memberof(change, directory, session)
        elif change.l_type == "member":
            await self._add_member(change, directory, session)

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
        password_utils: PasswordUtils,
    ) -> None:
        base_dir = None
        attrs = []

        if change.l_type in ("memberof", "member", "primarygroupid"):
            await self._add_group_attrs(change, directory, session)
            return

        for value in change.modification.vals:
            if change.l_type == "useraccountcontrol":
                uac_val = int(value)

                if not UserAccountControlFlag.is_value_valid(uac_val):
                    continue

                elif (
                    bool(uac_val & UserAccountControlFlag.ACCOUNTDISABLE)
                    and directory.user
                ):
                    if directory.path_dn == current_user.dn:
                        raise ModifyForbiddenError(
                            "Can't swith off own account.",
                        )

                    await kadmin.lock_principal(
                        directory.user.sam_account_name,
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
                    not bool(uac_val & UserAccountControlFlag.ACCOUNTDISABLE)
                    and directory.user
                ):
                    await unlock_principal(
                        directory.user.user_principal_name,
                        session,
                    )

                    await session.execute(
                        delete(Attribute)
                        .where(
                            or_(
                                qa(Attribute.name) == "nsAccountLock",
                                qa(Attribute.name) == "shadowExpire",
                            ),
                            qa(Attribute.directory) == directory,
                        ),
                    )  # fmt: skip

            if (
                change.l_type == "pwdlastset"
                and value == "0"
                and directory.user
            ):
                await kadmin.force_princ_pw_change(
                    directory.user.sam_account_name,
                )

            if change.l_type == directory.rdname:
                await session.execute(
                    update(Directory)
                    .filter(directory_table.c.id == directory.id)
                    .values(name=value),
                )

            if change.l_type in Directory.search_fields:
                await session.execute(
                    update(Directory)
                    .filter(directory_table.c.id == directory.id)
                    .values({change.l_type: value}),
                )

            elif (
                change.l_type in User.search_fields
                and directory.entity_type
                and directory.entity_type.name == EntityTypeNames.USER
                and directory.user
            ):
                if change.l_type == "accountexpires":
                    new_value = ft_to_dt(int(value)) if value != "0" else None
                else:
                    new_value = value  # type: ignore

                if change.l_type in ("userprincipalname", "samaccountname"):
                    if change.l_type == "userprincipalname":
                        new_user_principal_name = str(new_value)
                        new_sam_account_name = new_user_principal_name.split("@")[0]  # noqa: E501  # fmt: skip
                    elif change.l_type == "samaccountname":
                        if not base_dir:
                            base_dir = await self._get_base_dir(
                                directory,
                                session,
                            )

                        new_sam_account_name = str(new_value)
                        new_user_principal_name = f"{new_sam_account_name}@{base_dir.name}"  # noqa: E501  # fmt: skip

                    if directory.user.sam_account_name != new_sam_account_name:
                        await kadmin.rename_princ(
                            directory.user.sam_account_name,
                            new_sam_account_name,
                        )

                        directory.user.user_principal_name = new_user_principal_name  # noqa: E501  # fmt: skip
                        directory.user.sam_account_name = new_sam_account_name
                else:
                    await session.execute(
                        update(User)
                        .filter_by(directory=directory)
                        .values({change.l_type: new_value}),
                    )

            elif (
                change.l_type == "samaccountname"
                and directory.entity_type
                and directory.entity_type.name == EntityTypeNames.COMPUTER
            ):
                if not base_dir:
                    base_dir = await self._get_base_dir(
                        directory,
                        session,
                    )

                await self._modify_computer_samaccountname(
                    change,
                    kadmin,
                    base_dir,
                    value,
                )

                attrs.append(
                    Attribute(
                        name=change.modification.type,
                        value=value if isinstance(value, str) else None,
                        bvalue=value if isinstance(value, bytes) else None,
                        directory_id=directory.id,
                    ),
                )  # fmt: skip

            elif (
                change.l_type in ("userpassword", "unicodepwd")
                and directory.user
            ):
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

                directory.user.password = password_utils.get_password_hash(
                    value,
                )
                await password_use_cases.post_save_password_actions(
                    directory.user,
                )
                await kadmin.create_or_update_principal_pw(
                    directory.user.sam_account_name,
                    value,
                )

                await session_storage.clear_user_sessions(directory.user.id)

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

    async def _modify_computer_samaccountname(
        self,
        change: Changes,
        kadmin: AbstractKadmin,
        base_dir: Directory,
        new_sam_account_name: bytes | str,
    ) -> None:
        old_sam_account_name = self._old_vals.get(change.modification.type)
        new_sam_account_name = str(new_sam_account_name)

        if not old_sam_account_name:
            raise ModifyForbiddenError("Old sAMAccountName value not found.")

        if old_sam_account_name != new_sam_account_name:
            await kadmin.rename_princ(
                f"host/{old_sam_account_name}",
                f"host/{new_sam_account_name}",
            )
            await kadmin.rename_princ(
                f"host/{old_sam_account_name}.{base_dir.name}",
                f"host/{new_sam_account_name}.{base_dir.name}",
            )

    async def _get_base_dir(
        self,
        directory: Directory,
        session: AsyncSession,
    ) -> Directory:
        base_dir = None

        for base_directory in await get_base_directories(session):
            if is_dn_in_base_directory(
                base_directory,
                directory.path_dn,
            ):
                base_dir = base_directory
                break
        else:
            raise ModifyForbiddenError("Base directory not found.")

        return base_dir
