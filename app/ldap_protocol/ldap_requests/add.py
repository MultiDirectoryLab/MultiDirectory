"""Add protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

import httpx
from enums import AceType
from pydantic import Field, SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    AddResponse,
    PartialAttribute,
)
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.policies.password_policy import PasswordPolicySchema
from ldap_protocol.roles.access_manager import AccessManager
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.helpers import (
    create_integer_hash,
    create_user_name,
    ft_now,
    is_dn_in_base_directory,
)
from ldap_protocol.utils.queries import (
    create_object_sid,
    get_base_directories,
    get_group,
    get_groups,
    get_path_filter,
    get_search_path,
    validate_entry,
)
from models import Attribute, Directory, Group, User
from security import get_password_hash

from .base import BaseRequest


class AddRequest(BaseRequest):
    """Add new entry.

    ```
    AddRequest ::= [APPLICATION 8] SEQUENCE {
        entry           LDAPDN,
        attributes      AttributeList
    }

    AttributeList ::= SEQUENCE OF attribute Attribute

    password - only JSON API field, added only for user creation,
    skips validation if target entity is not user.
    ```
    """

    PROTOCOL_OP: ClassVar[int] = 8

    entry: str = Field(..., description="Any `DistinguishedName`")
    attributes: list[PartialAttribute]

    password: SecretStr | None = Field(None, examples=["password"])

    @property
    def attr_names(self) -> dict[str, list[str | bytes]]:
        return {attr.l_name: attr.vals for attr in self.attributes}

    @property
    def attributes_dict(self) -> dict[str, list[str | bytes]]:
        return {attr.type: attr.vals for attr in self.attributes}

    @classmethod
    def from_data(cls, data: ASN1Row) -> "AddRequest":
        """Deserialize."""
        entry, attributes = data  # type: ignore
        attributes = [
            PartialAttribute(
                type=attr.value[0].value,
                vals=[val.value for val in attr.value[1].value],
            )
            for attr in attributes.value  # type: ignore
        ]
        return cls(entry=entry.value, attributes=attributes)  # type: ignore

    async def handle(  # noqa: C901
        self,
        session: AsyncSession,
        ldap_session: LDAPSession,
        kadmin: AbstractKadmin,
        entity_type_dao: EntityTypeDAO,
        access_manager: AccessManager,
        role_use_case: RoleUseCase,
    ) -> AsyncGenerator[AddResponse, None]:
        """Add request handler."""
        if not ldap_session.user:
            yield AddResponse(**INVALID_ACCESS_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield AddResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        if not ldap_session.user.role_ids:
            yield AddResponse(result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS)
            return

        root_dn = get_search_path(self.entry)

        exists_q = select(
            select(Directory)
            .filter(get_path_filter(root_dn)).exists()
        )  # fmt: skip

        if await session.scalar(exists_q) is True:
            yield AddResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
            return

        for base_directory in await get_base_directories(session):
            if is_dn_in_base_directory(base_directory, self.entry):
                base_dn = base_directory
                break
        else:
            yield AddResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        parent_path = get_path_filter(root_dn[:-1])
        new_dn, name = self.entry.split(",")[0].split("=")

        parent_query = select(Directory).filter(parent_path)

        parent_query = access_manager.mutate_query_with_ace_load(
            user_role_ids=ldap_session.user.role_ids,
            query=parent_query,
            ace_types=[AceType.CREATE_CHILD],
        )

        parent = await session.scalar(parent_query)
        if not parent:
            yield AddResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        object_class_names = set(
            self.attributes_dict.get("objectClass", [])
            + self.attributes_dict.get("objectclass", [])
        )

        entity_type = (
            await entity_type_dao.get_entity_type_by_object_class_names(
                object_class_names=object_class_names,  # type: ignore
            )
        )

        can_add = access_manager.check_entity_level_access(
            aces=parent.access_control_entries,
            entity_type_id=entity_type.id if entity_type else None,
        )

        if not can_add:
            yield AddResponse(result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS)
            return

        if self.password is not None:
            validator = await PasswordPolicySchema.get_policy_settings(session)
            raw_password = self.password.get_secret_value()
            errors = await validator.validate_password_with_policy(
                password=raw_password,
                user=None,
            )

            if errors:
                yield AddResponse(
                    result_code=LDAPCodes.OPERATIONS_ERROR,
                    errorMessage="; ".join(errors),
                )
                return

        try:
            new_dir = Directory(
                object_class="",
                name=name,
                parent=parent,
            )

            new_dir.create_path(parent, new_dn)
            session.add(new_dir)

            await session.flush()

            new_dir.object_sid = create_object_sid(base_dn, new_dir.id)
            await session.flush()
        except IntegrityError:
            await session.rollback()
            yield AddResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
            return

        group = None
        user = None
        items_to_add: list[Group | User | Directory | Attribute] = []
        attributes = []
        parent_groups: list[Group] = []
        user_attributes: dict[str, str] = {}
        group_attributes: list[str] = []
        user_fields = User.search_fields.keys() | User.fields.keys()

        attributes.append(
            Attribute(
                name=new_dn,
                value=name,
                directory=new_dir,
            )
        )

        for attr in self.attributes:
            # NOTE: Do not create a duplicate if the user has sent the rdn
            # in the attributes
            if (
                attr.l_name in Directory.ro_fields
                or attr.l_name
                in (
                    "userpassword",
                    "unicodepwd",
                )
                or attr.l_name == new_dir.rdname
            ):
                continue

            for value in attr.vals:
                if (
                    attr.l_name in user_fields
                    or attr.type == "userAccountControl"
                ):
                    if not isinstance(value, str):
                        raise TypeError
                    user_attributes[attr.type] = value

                elif attr.type == "memberOf":
                    if not isinstance(value, str):
                        raise TypeError
                    group_attributes.append(value)

                else:
                    attributes.append(
                        Attribute(
                            name=attr.type,
                            value=value if isinstance(value, str) else None,
                            bvalue=value if isinstance(value, bytes) else None,
                            directory=new_dir,
                        ),
                    )

        parent_groups = await get_groups(group_attributes, session)
        is_group = "group" in self.attributes_dict.get("objectClass", [])
        is_user = (
            "sAMAccountName" in user_attributes
            or "userPrincipalName" in user_attributes
        )
        is_computer = "computer" in self.attributes_dict.get("objectClass", [])

        if is_user:
            parent_groups.append(
                (await get_group("domain users", session)).group,
            )

            sam_accout_name = user_attributes.get(
                "sAMAccountName",
                create_user_name(new_dir.id),
            )
            user_principal_name = user_attributes.get(
                "userPrincipalName",
                f"{sam_accout_name!r}@{base_dn.name}",
            )
            user = User(
                sam_accout_name=sam_accout_name,
                user_principal_name=user_principal_name,
                mail=user_attributes.get("mail"),
                display_name=user_attributes.get("displayName"),
                directory=new_dir,
                password_history=[],
            )

            if self.password is not None:
                user.password = get_password_hash(raw_password)

            items_to_add.append(user)
            user.groups.extend(parent_groups)

            uac_value: str = user_attributes.get("userAccountControl", "0")

            if not UserAccountControlFlag.is_value_valid(uac_value):
                uac_value = str(UserAccountControlFlag.NORMAL_ACCOUNT)

            attributes.append(
                Attribute(
                    name="userAccountControl",
                    value=uac_value,
                    directory=new_dir,
                ),
            )

            for attr, value in {  # type: ignore
                "loginShell": "/bin/bash",
                "uidNumber": str(create_integer_hash(user.sam_accout_name)),
                "homeDirectory": f"/home/{user.sam_accout_name}",
            }.items():
                if attr in user_attributes:
                    value = user_attributes[attr]  # type: ignore
                    del user_attributes[attr]  # type: ignore

                attributes.append(
                    Attribute(
                        name=attr,
                        value=value,
                        directory=new_dir,
                    ),
                )

            attributes.append(
                Attribute(
                    name="pwdLastSet",
                    value=ft_now(),
                    directory=new_dir,
                ),
            )

        elif is_group:
            group = Group(directory=new_dir)
            items_to_add.append(group)
            group.parent_groups.extend(parent_groups)

        elif is_computer and "useraccountcontrol" not in self.attr_names:
            attributes.append(
                Attribute(
                    name="userAccountControl",
                    value=str(
                        UserAccountControlFlag.WORKSTATION_TRUST_ACCOUNT,
                    ),
                    directory=new_dir,
                ),
            )

        if (is_user or is_group) and "gidnumber" not in self.attr_names:
            reverse_d_name = new_dir.name[::-1]
            value = (
                "513" if is_user else str(create_integer_hash(reverse_d_name))
            )
            attributes.append(
                Attribute(
                    name="gidNumber",  # reverse dir name if it matches samAN
                    value=value,
                    directory=new_dir,
                ),
            )

        try:
            items_to_add.extend(attributes)
            session.add_all(items_to_add)
            await session.flush()

            await session.refresh(
                instance=new_dir,
                attribute_names=["attributes"],
                with_for_update=None,
            )
            await entity_type_dao.attach_entity_type_to_directory(
                directory=new_dir,
                is_system_entity_type=False,
            )
            await role_use_case.inherit_parent_aces(
                parent_directory=parent,
                directory=new_dir,
            )
            await session.flush()
        except IntegrityError:
            await session.rollback()
            yield AddResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
        else:
            try:
                # in case server is not available: raise error and rollback
                # stub cannot raise error
                if user:
                    pw = (
                        self.password.get_secret_value()
                        if self.password
                        else None
                    )
                    await kadmin.add_principal(user.get_upn_prefix(), pw)
                if is_computer:
                    await kadmin.add_principal(
                        f"{new_dir.host_principal}.{base_dn.name}",
                        None,
                    )
                    await kadmin.add_principal(new_dir.host_principal, None)
            except KRBAPIError:
                await session.rollback()
                yield AddResponse(
                    result_code=LDAPCodes.UNAVAILABLE,
                    errorMessage="KerberosError",
                )
                return
            except httpx.TimeoutException:
                pass

            yield AddResponse(result_code=LDAPCodes.SUCCESS)

    @classmethod
    def from_dict(
        cls,
        entry: str,
        attributes: dict[str, list[str]],
        password: str | None = None,
    ) -> "AddRequest":
        """Create AddRequest from dict.

        :param str entry: entry
        :param dict[str, list[str]] attributes: dict of attrs
        :return AddRequest: instance
        """
        return AddRequest(
            entry=entry,
            password=password,
            attributes=[
                PartialAttribute(type=name, vals=vals)
                for name, vals in attributes.items()
            ],
        )
