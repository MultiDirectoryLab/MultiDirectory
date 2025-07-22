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
from sqlalchemy.orm import joinedload, selectinload, with_loader_criteria

from config import Settings
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession, UserSchema
from ldap_protocol.kerberos import (
    AbstractKadmin,
    KRBAPIError,
    unlock_principal,
)
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import ModifyResponse, PartialAttribute
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.objects import Changes, Operation
from ldap_protocol.policies.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.roles.access_manager import AccessManager
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
from models import (
    AccessControlEntry,
    AceType,
    Attribute,
    Directory,
    Group,
    User,
)
from security import get_password_hash

from .base import BaseRequest

MODIFY_EXCEPTION_STACK = (
    ValueError,
    IntegrityError,
    KRBAPIError,
    RecursionError,
    PermissionError,
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

    PROTOCOL_OP: ClassVar[int] = 6

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
        policy: PasswordPolicySchema,
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
        ldap_session: LDAPSession,
        session: AsyncSession,
        session_storage: SessionStorage,
        kadmin: AbstractKadmin,
        settings: Settings,
        entity_type_dao: EntityTypeDAO,
        access_manager: AccessManager,
    ) -> AsyncGenerator[ModifyResponse, None]:
        """Change request handler."""
        if not ldap_session.user:
            yield ModifyResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
            return

        if not validate_entry(self.object.lower()):
            yield ModifyResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        if not ldap_session.user.role_ids:
            yield ModifyResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS
            )
            return

        policy = await PasswordPolicySchema.get_policy_settings(session)
        query = self._get_dir_query(ldap_session.user)

        directory = await session.scalar(query)

        if not directory:
            yield ModifyResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        can_modify = access_manager.check_modify_access(
            changes=self.changes,
            aces=directory.access_control_entries,
            entity_type_id=directory.entity_type_id,
        )

        names = {change.get_name() for change in self.changes}

        password_change_requested = self._check_password_change_requested(
            names,
            directory,
            ldap_session.user.directory_id,
        )

        if not can_modify and not password_change_requested:
            yield ModifyResponse(
                result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS,
            )
            return

        for change in self.changes:
            if change.modification.type in Directory.ro_fields:
                continue

            self._update_password_expiration(change, policy)

            add_args = (
                change,
                directory,
                session,
                session_storage,
                kadmin,
                settings,
            )

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
            except MODIFY_EXCEPTION_STACK as err:
                await session.rollback()
                result_code, message = self._match_bad_response(err)
                yield ModifyResponse(result_code=result_code, message=message)
                return

            await session.refresh(
                instance=directory,
                attribute_names=["groups", "attributes"],
            )

        if "objectclass" in names:
            await entity_type_dao.attach_entity_type_to_directory(
                directory=directory,
                is_system_entity_type=False,
            )
        await session.commit()
        yield ModifyResponse(result_code=LDAPCodes.SUCCESS)

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

            case _:
                raise err

    def _mutate_query_with_ace_load(
        self,
        user_role_ids: list[int],
        query: Select,
    ) -> Select:
        """Mutate query to load access control entries.

        :param user_role_ids: list of user role ids
        :param query: SQLAlchemy query to mutate
        :return: mutated query with access control entries loaded
        """
        return query.options(
            selectinload(Directory.access_control_entries).joinedload(
                AccessControlEntry.attribute_type
            ),
            with_loader_criteria(
                AccessControlEntry,
                and_(
                    AccessControlEntry.role_id.in_(user_role_ids),
                    AccessControlEntry.ace_type.in_(
                        [AceType.DELETE, AceType.WRITE]
                    ),
                ),
            ),
        )

    def _get_dir_query(self, user: UserSchema) -> Select:
        query = (
            select(Directory)
            .options(
                selectinload(Directory.attributes),
                selectinload(Directory.groups),
                joinedload(Directory.group).selectinload(Group.members),
            )
            .filter(get_filter_from_path(self.object))
        )
        return self._mutate_query_with_ace_load(user.role_ids, query)

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

    async def _delete(
        self,
        change: Changes,
        directory: Directory,
        session: AsyncSession,
        name_only: bool = False,
    ) -> None:
        attrs = []
        name = change.modification.type.lower()

        if name == "memberof":
            groups = await get_groups(change.modification.vals, session)  # type: ignore

            if not change.modification.vals:
                directory.groups.clear()

            elif change.operation == Operation.REPLACE:
                directory.groups = list(set(directory.groups) & set(groups))

            else:
                for group in groups:
                    directory.groups.remove(group)

            return

        if name == "member":
            members = await get_directories(change.modification.vals, session)  # type: ignore

            if not change.modification.vals:
                directory.group.members.clear()

            elif change.operation == Operation.REPLACE:
                directory.group.members = list(
                    set(directory.group.members) & set(members),
                )

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

                    attrs.append(
                        and_(
                            Attribute.name == change.modification.type,
                            condition,
                        ),
                    )

        if attrs:
            del_query = (
                delete(Attribute)
                .filter(Attribute.directory == directory, or_(*attrs))
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
                        .filter(
                            Attribute.name == "nsAccountLock",
                            Attribute.directory == directory,
                        )
                    )  # fmt: skip

                    await session.execute(
                        delete(Attribute)
                        .filter(
                            Attribute.name == "shadowExpire",
                            Attribute.directory == directory,
                        ),
                    )  # fmt: skip

            if name == "pwdlastset" and value == "0" and directory.user:
                await kadmin.force_princ_pw_change(
                    directory.user.get_upn_prefix(),
                )

            if name == directory.rdname:
                await session.execute(
                    update(Directory)
                    .filter(Directory.id == directory.id)
                    .values(name=value),
                )

            if name in Directory.search_fields:
                await session.execute(
                    update(Directory)
                    .filter(Directory.id == directory.id)
                    .values({name: value}),
                )

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

                if name == "accountexpires":
                    new_value = ft_to_dt(int(value)) if value != "0" else None
                else:
                    new_value = value  # type: ignore

                await session.execute(
                    update(User)
                    .filter(User.directory == directory)
                    .values({name: new_value}),
                )

            elif name in Group.search_fields and directory.group:
                await session.execute(
                    update(Group)
                    .filter(Group.directory == directory)
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

                validator = await PasswordPolicySchema.get_policy_settings(
                    session
                )

                p_last_set = await validator.get_pwd_last_set(
                    session,
                    directory.id,
                )

                errors = await validator.validate_password_with_policy(
                    password=value,
                    user=directory.user,
                )

                if validator.validate_min_age(p_last_set):
                    errors.append("Minimum age violation")

                if errors:
                    raise PermissionError(
                        f"Password policy violation: {errors}",
                    )

                directory.user.password = get_password_hash(value)
                await post_save_password_actions(directory.user, session)
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
                        directory=directory,
                    )
                )

        session.add_all(attrs)
