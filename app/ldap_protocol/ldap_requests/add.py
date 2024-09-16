"""Add protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from pydantic import Field, SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.access_policy import mutate_ap
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    AddResponse,
    PartialAttribute,
)
from ldap_protocol.password_policy import PasswordPolicySchema
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils import (
    create_integer_hash,
    create_object_sid,
    create_user_name,
    ft_now,
    get_base_directories,
    get_group,
    get_groups,
    get_path_filter,
    get_search_path,
    is_dn_in_base_directory,
    validate_entry,
)
from models.ldap3 import Attribute, Directory, Group, User
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

    entry: str = Field(..., description='Any `DistinguishedName`')
    attributes: list[PartialAttribute]

    password: SecretStr | None = Field(None, examples=['password'])

    @property
    def attr_names(self) -> dict[str, list[str]]:  # noqa
        return {attr.type.lower(): attr.vals for attr in self.attributes}

    @classmethod
    def from_data(cls, data: ASN1Row) -> 'AddRequest':  # noqa: D102
        entry, attributes = data
        attributes = [
            PartialAttribute(
                type=attr.value[0].value,
                vals=[val.value for val in attr.value[1].value])
            for attr in attributes.value
        ]
        return cls(entry=entry.value, attributes=attributes)

    async def handle(
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

        exists_q = select(select(Directory).join(Directory.path).filter(
            get_path_filter(root_dn)).exists())

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
        new_dn, name = self.entry.split(',')[0].split('=')

        query = (  # noqa: ECE001
            select(Directory)
            .join(Directory.path)
            .options(
                selectinload(Directory.paths),
                selectinload(Directory.access_policies))
            .filter(parent_path))

        parent = await session.scalar(mutate_ap(query, ldap_session.user))

        if not parent:
            yield AddResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
            return

        if not await session.scalar(
                mutate_ap(query, ldap_session.user, "add")):
            yield AddResponse(result_code=LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS)
            return

        is_computer = 'computer' in self.attr_names.get('objectclass', [])

        new_dir = Directory(
            object_class='computer' if is_computer else '',
            name=name,
            parent=parent,
        )

        new_dir.access_policies.extend(parent.access_policies)
        await session.flush()

        path = new_dir.create_path(parent, new_dn)
        new_dir.depth = len(path.path)

        if self.password is not None:
            validator = await PasswordPolicySchema\
                .get_policy_settings(session)
            raw_password = self.password.get_secret_value()
            errors = await validator.validate_password_with_policy(
                raw_password, None)

            if errors:
                yield AddResponse(
                    result_code=LDAPCodes.OPERATIONS_ERROR,
                    errorMessage='; '.join(errors),
                )
                return

        try:
            session.add_all([new_dir, path])
            path.directories.extend(
                [p.endpoint for p in parent.paths + [path]])
            await session.flush()
            new_dir.object_sid = create_object_sid(base_dn, new_dir.id)
            await session.flush()
        except IntegrityError:
            await session.rollback()
            yield AddResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
            return

        group = None
        user = None
        items_to_add = []
        attributes = []
        parent_groups: list[Group] = []
        user_attributes = {}
        group_attributes: list[str] = []
        user_fields = User.search_fields.values()

        for attr in self.attributes:
            lname = attr.type.lower()
            for value in attr.vals:
                if lname in Directory.ro_fields or lname in (
                        "userpassword", 'unicodepwd', 'useraccountcontrol'):
                    continue

                if attr.type in user_fields:
                    user_attributes[attr.type] = value

                elif attr.type == 'memberOf':
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
        is_group = 'group' in self.attr_names.get('objectclass', [])
        is_user = 'sAMAccountName' in user_attributes\
            or 'userPrincipalName' in user_attributes

        if is_user:
            parent_groups.append(
                (await get_group('domain users', session)).group)

            sam_accout_name = user_attributes.get(
                'sAMAccountName', create_user_name(new_dir.id))
            user_principal_name = user_attributes.get(
                'userPrincipalName', f"{sam_accout_name}@{base_dn.name}")
            user = User(
                sam_accout_name=sam_accout_name,
                user_principal_name=user_principal_name,
                mail=user_attributes.get('mail'),
                display_name=user_attributes.get('displayName'),
                directory=new_dir,
                password_history=[],
            )

            if self.password is not None:
                user.password = get_password_hash(raw_password)

            items_to_add.append(user)
            user.groups.extend(parent_groups)

            attributes.append(Attribute(
                name='userAccountControl',
                value=str(UserAccountControlFlag.NORMAL_ACCOUNT),
                directory=new_dir))

            attributes.append(Attribute(
                name='uidNumber',
                value=str(create_integer_hash(user.sam_accout_name)),
                directory=new_dir))

            attributes.append(Attribute(
                name='homeDirectory',
                value=f'/home/{user.sam_accout_name}',
                directory=new_dir))

            attributes.append(Attribute(
                name='loginShell',
                value='/bin/bash',
                directory=new_dir))

            attributes.append(Attribute(
                name='pwdLastSet',
                value=ft_now(),
                directory=new_dir))

        elif is_group:
            group = Group(directory=new_dir)
            items_to_add.append(group)
            group.parent_groups.extend(parent_groups)

        elif is_computer:
            attributes.append(Attribute(
                name='userAccountControl',
                value=str(UserAccountControlFlag.WORKSTATION_TRUST_ACCOUNT),
                directory=new_dir))

        if is_user or is_group:
            attributes.append(Attribute(
                name='gidNumber',  # reverse dir name if it matches samAN
                value=str(create_integer_hash(new_dir.name[::-1])),
                directory=new_dir))

        try:
            items_to_add.extend(attributes)
            session.add_all(items_to_add)
            await session.flush()
        except IntegrityError:
            await session.rollback()
            yield AddResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
        else:
            pw = (
                self.password.get_secret_value()
                if self.password else None)

            try:
                # in case server is not available: raise error and rollback
                # stub cannot raise error
                if user:
                    await kadmin.add_principal(
                        user.get_upn_prefix(), pw)
                if is_computer:
                    await kadmin.add_principal(
                        f"HOST/{new_dir.name}.{base_dn.name}", pw)
                    await kadmin.add_principal(
                        f"HOST/{new_dir.name}", pw)
            except KRBAPIError:
                await session.rollback()
                yield AddResponse(
                    result_code=LDAPCodes.UNAVAILABLE,
                    errorMessage="KerberosError",
                )
                return

            yield AddResponse(result_code=LDAPCodes.SUCCESS)

    @classmethod
    def from_dict(
        cls, entry: str,
        attributes: dict[str, list[str]],
        password: str | None = None,
    ) -> 'AddRequest':
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
                for name, vals in attributes.items()],
        )
