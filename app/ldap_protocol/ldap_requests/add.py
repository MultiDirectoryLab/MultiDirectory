"""Add protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar, cast

import httpx
from pydantic import Field, SecretStr
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    AddResponse,
    PartialAttribute,
)
from ldap_protocol.ldap_schema.flat_ldap_schema import (
    validate_attributes_by_ldap_schema,
    validate_chunck_object_classes_by_ldap_schema,
)
from ldap_protocol.policies.access_policy import mutate_ap
from ldap_protocol.policies.password_policy import PasswordPolicySchema
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
        return {attr.type.lower(): attr.vals for attr in self.attributes}

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
    ) -> AsyncGenerator[AddResponse, None]:
        """Add request handler."""
        if not ldap_session.user:
            yield AddResponse(**INVALID_ACCESS_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield AddResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
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

        query = (
            select(Directory)
            .options(selectinload(Directory.access_policies))
            .filter(parent_path)
        )

        parent = await session.scalar(mutate_ap(query, ldap_session.user))

        if not parent:
            yield AddResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        if not await session.scalar(
            mutate_ap(query, ldap_session.user, "add"),
        ):
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
                    error_message="; ".join(errors),
                )
                return

        try:
            new_dir = Directory(
                object_class="",
                name=name,
                parent=parent,
                access_policies=parent.access_policies,
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
        attributes: list[Attribute] = []
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
            lname = attr.type.lower()

            # NOTE: Do not create a duplicate if the user has sent the rdn
            # in the attributes
            if (
                lname == new_dir.rdname
                or lname in Directory.ro_fields
                or lname in ("userpassword", "unicodepwd")
            ):
                continue

            for value in attr.vals:
                if lname in user_fields or lname == "useraccountcontrol":
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
        is_group = "group" in self.attr_names.get("objectclass", [])
        is_user = (
            "sAMAccountName" in user_attributes
            or "userPrincipalName" in user_attributes
        )
        is_computer = "computer" in self.attr_names.get("objectclass", [])

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

        object_class_names = self._get_object_class_names()
        if not object_class_names:
            yield AddResponse(
                result_code=LDAPCodes.OBJECT_CLASS_VIOLATION,
                error_message=f"Directory {new_dir} attributes must have\
                at least one 'objectClass'.",
            )
            return

        classes_validation_result = (
            await validate_chunck_object_classes_by_ldap_schema(
                session,
                object_class_names,
            )
        )
        for result_code, messages in classes_validation_result.alerts.items():
            yield AddResponse(
                result_code=result_code,
                error_message=", ".join(messages),
            )
            return

        attrs_validation_result = await validate_attributes_by_ldap_schema(
            session,
            attributes,
            object_class_names,
        )
        for result_code, messages in attrs_validation_result.alerts.items():
            yield AddResponse(
                result_code=result_code,
                error_message=", ".join(messages),
            )
            return

        for attribute in attrs_validation_result.attributes_rejected:
            attribute = cast("Attribute", attribute)
            if inspect(attribute).persistent:
                await session.delete(attribute)

        try:
            items = cast(
                "list[Attribute]",
                attrs_validation_result.attributes_accepted,
            )
            items_to_add.extend(items)
            session.add_all(items_to_add)
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
                    error_message="KerberosError",
                )
                return
            except httpx.TimeoutException:
                pass

            yield AddResponse(result_code=LDAPCodes.SUCCESS)

    def _get_object_class_names(self) -> set[str]:
        object_class_values = self.attr_names.get("objectclass", [])
        object_class_names = set()
        for object_class_name in object_class_values:
            if isinstance(object_class_name, bytes):
                object_class_name = object_class_name.decode()
            object_class_names.add(object_class_name)
        return object_class_names

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
