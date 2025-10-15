"""Add protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

import httpx
from pydantic import Field, SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from entities import Attribute, Directory, Group, User
from enums import AceType
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.kerberos import KRBAPIError
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    AddResponse,
    PartialAttribute,
)
from ldap_protocol.objects import ProtocolRequests
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.const import (
    DOMAIN_COMPUTERS_GROUP_NAME,
    DOMAIN_USERS_GROUP_NAME,
)
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

from .base import BaseRequest
from .contexts import LDAPAddRequestContext


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

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.ADD

    entry: str = Field(..., description="Any `DistinguishedName`")
    attributes: list[PartialAttribute]

    password: SecretStr | None = Field(None, examples=["password"])

    @property
    def attr_names(self) -> dict[str, list[str | bytes]]:
        return {attr.l_name: attr.vals for attr in self.attributes}

    @property
    def attributes_dict(self) -> dict[str, list[str | bytes]]:
        return {attr.type: attr.vals for attr in self.attributes}

    @property
    def object_class_names(self) -> set[str]:
        return {
            str(name)
            for name in (
                self.attributes_dict.get("objectClass", [])
                + self.attributes_dict.get("objectclass", [])
            )
        }

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
        ctx: LDAPAddRequestContext,
    ) -> AsyncGenerator[AddResponse, None]:
        """Add request handler."""
        if not ctx.ldap_session.user:
            yield AddResponse(**INVALID_ACCESS_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield AddResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        if not ctx.ldap_session.user.role_ids:
            yield AddResponse(result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS)
            return

        root_dn = get_search_path(self.entry)

        exists_q = select(
            select(Directory)
            .filter(get_path_filter(root_dn)).exists(),
        )  # fmt: skip

        if await ctx.session.scalar(exists_q) is True:
            yield AddResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
            return

        for base_directory in await get_base_directories(ctx.session):
            if is_dn_in_base_directory(base_directory, self.entry):
                base_dn = base_directory
                break
        else:
            yield AddResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        parent_path = get_path_filter(root_dn[:-1])
        new_dn, name = self.entry.split(",")[0].split("=")
        parent_query = select(Directory).filter(parent_path)

        parent_query = ctx.access_manager.mutate_query_with_ace_load(
            user_role_ids=ctx.ldap_session.user.role_ids,
            query=parent_query,
            ace_types=[AceType.CREATE_CHILD],
        )

        parent = await ctx.session.scalar(parent_query)
        if not parent:
            yield AddResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        entity_type = (
            await ctx.entity_type_dao.get_entity_type_by_object_class_names(
                object_class_names=self.object_class_names,
            )
        )

        can_add = ctx.access_manager.check_entity_level_access(
            aces=parent.access_control_entries,
            entity_type_id=entity_type.id if entity_type else None,
            entity_type_name=entity_type.name if entity_type else None,
            user=ctx.ldap_session.user,
            parent_object_class=parent.object_class,
        )

        if not can_add:
            yield AddResponse(result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS)
            return

        if self.password is not None:
            raw_password = self.password.get_secret_value()
            errors = await ctx.password_use_cases.check_password_violations(
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
            ctx.session.add(new_dir)

            await ctx.session.flush()
            await ctx.session.refresh(new_dir, ["id"])

            new_dir.object_sid = create_object_sid(base_dn, new_dir.id)
            await ctx.session.flush()
        except IntegrityError:
            await ctx.session.rollback()
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
                directory_id=new_dir.id,
            ),
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
                    if value in group_attributes:
                        continue
                    group_attributes.append(value)

                else:
                    attributes.append(
                        Attribute(
                            name=attr.type,
                            value=value if isinstance(value, str) else None,
                            bvalue=value if isinstance(value, bytes) else None,
                            directory_id=new_dir.id,
                        ),
                    )

        parent_groups = await get_groups(group_attributes, ctx.session)
        is_group = "group" in self.attributes_dict.get("objectClass", [])
        is_user = (
            "sAMAccountName" in user_attributes
            or "userPrincipalName" in user_attributes
        )
        is_computer = "computer" in self.attributes_dict.get("objectClass", [])

        if is_user:
            if not any(
                group.directory.name.lower() == DOMAIN_USERS_GROUP_NAME
                for group in parent_groups
            ):
                parent_groups.append(
                    await get_group(DOMAIN_USERS_GROUP_NAME, ctx.session),
                )

            sam_account_name = user_attributes.get(
                "sAMAccountName",
                create_user_name(new_dir.id),
            )
            user_principal_name = user_attributes.get(
                "userPrincipalName",
                f"{sam_account_name!r}@{base_dn.name}",
            )
            user = User(
                sam_account_name=sam_account_name,
                user_principal_name=user_principal_name,
                mail=user_attributes.get("mail"),
                display_name=user_attributes.get("displayName"),
                directory_id=new_dir.id,
                password_history=[],
            )

            if self.password is not None:
                user.password = ctx.password_validator.get_password_hash(
                    raw_password,
                )

            items_to_add.append(user)
            user.groups.extend(parent_groups)

            uac_value: str = user_attributes.get("userAccountControl", "0")

            if not UserAccountControlFlag.is_value_valid(uac_value):
                uac_value = str(UserAccountControlFlag.NORMAL_ACCOUNT)

            attributes.append(
                Attribute(
                    name="userAccountControl",
                    value=uac_value,
                    directory_id=new_dir.id,
                ),
            )

            for uattr, value in {
                "loginShell": "/bin/bash",
                "uidNumber": str(create_integer_hash(user.sam_account_name)),
                "homeDirectory": f"/home/{user.sam_account_name}",
            }.items():
                if uattr in user_attributes:
                    value = user_attributes[uattr]
                    del user_attributes[uattr]

                attributes.append(
                    Attribute(
                        name=uattr,
                        value=value,
                        directory_id=new_dir.id,
                    ),
                )

            attributes.append(
                Attribute(
                    name="pwdLastSet",
                    value=ft_now(),
                    directory_id=new_dir.id,
                ),
            )

        elif is_group:
            group = Group(directory_id=new_dir.id)
            items_to_add.append(group)
            group.parent_groups.extend(parent_groups)

        elif is_computer and "useraccountcontrol" not in self.attr_names:
            if not any(
                group.directory.name.lower() == DOMAIN_COMPUTERS_GROUP_NAME
                for group in parent_groups
            ):
                parent_groups.append(
                    await get_group(
                        DOMAIN_COMPUTERS_GROUP_NAME,
                        ctx.session,
                    ),
                )
            await ctx.session.refresh(
                instance=new_dir,
                attribute_names=["groups"],
                with_for_update=None,
            )
            new_dir.groups.extend(parent_groups)
            attributes.append(
                Attribute(
                    name="userAccountControl",
                    value=str(
                        UserAccountControlFlag.WORKSTATION_TRUST_ACCOUNT,
                    ),
                    directory_id=new_dir.id,
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
                    directory_id=new_dir.id,
                ),
            )

        if is_computer or is_user:
            attributes.append(
                Attribute(
                    name="primaryGroupID",
                    value=parent_groups[-1].directory.relative_id,
                    directory_id=new_dir.id,
                ),
            )

        try:
            items_to_add.extend(attributes)
            ctx.session.add_all(items_to_add)
            await ctx.session.flush()

            await ctx.session.refresh(
                instance=new_dir,
                attribute_names=["attributes"],
                with_for_update=None,
            )
            await ctx.entity_type_dao.attach_entity_type_to_directory(
                directory=new_dir,
                is_system_entity_type=False,
            )
            await ctx.role_use_case.inherit_parent_aces(
                parent_directory=parent,
                directory=new_dir,
            )
            await ctx.session.flush()
        except IntegrityError:
            await ctx.session.rollback()
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
                    await ctx.kadmin.add_principal(user.get_upn_prefix(), pw)
                if is_computer:
                    await ctx.kadmin.add_principal(
                        f"{new_dir.host_principal}.{base_dn.name}",
                        None,
                    )
                    await ctx.kadmin.add_principal(
                        new_dir.host_principal,
                        None,
                    )
            except KRBAPIError:
                await ctx.session.rollback()
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
