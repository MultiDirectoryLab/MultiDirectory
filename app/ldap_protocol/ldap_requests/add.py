"""Add protocol."""

from typing import AsyncGenerator, ClassVar

from pydantic import Field, SecretStr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from ldap_protocol.dialogue import LDAPCodes, Session
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    AddResponse,
    PartialAttribute,
)
from ldap_protocol.utils import get_base_dn, get_groups, validate_entry
from models.ldap3 import Attribute, Directory, Group, Path, User
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

    entry: str
    attributes: list[PartialAttribute]

    password: SecretStr | None = Field(None, example='password')

    @property
    def attr_names(self):  # noqa
        return {attr.type: attr.vals for attr in self.attributes}

    @classmethod
    def from_data(cls, data):  # noqa: D102
        entry, attributes = data
        attributes = [
            PartialAttribute(
                type=attr.value[0].value,
                vals=[val.value for val in attr.value[1].value])
            for attr in attributes.value
        ]
        return cls(entry=entry.value, attributes=attributes)

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[AddResponse, None]:
        """Add request handler."""
        if not ldap_session.user:
            yield AddResponse(**INVALID_ACCESS_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield AddResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        base_dn = await get_base_dn(session)
        obj = self.entry.lower().removesuffix(
            ',' + base_dn.lower()).split(',')
        has_no_parent = len(obj) == 1

        new_dn, name = obj.pop(0).split('=')

        if has_no_parent:
            new_dir = Directory(
                object_class='',
                name=name,
            )
            path = new_dir.create_path(dn=new_dn)

        else:
            search_path = reversed(obj)
            query = select(Directory)\
                .join(Directory.path)\
                .options(selectinload(Directory.paths))\
                .filter(Path.path == search_path)
            parent = await session.scalar(query)

            if not parent:
                yield AddResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
                return

            new_dir = Directory(
                object_class='',
                name=name,
                parent=parent,
            )
            path = new_dir.create_path(parent, new_dn)

        group = None
        user = None
        items_to_add = []
        attributes = []
        parent_groups: list[Group] = []
        user_attributes = {}
        group_attributes: list[str] = []
        user_fields = User.search_fields.values()

        for attr in self.attributes:
            for value in attr.vals:
                if attr.type in user_fields:
                    user_attributes[attr.type] = value

                elif attr.type == 'memberOf':
                    group_attributes.append(value)
                else:
                    attributes.append(Attribute(
                        name=attr.type, value=value, directory=new_dir))

        parent_groups = await get_groups(group_attributes, session)

        if 'sAMAccountName' in user_attributes\
                or 'userPrincipalName' in user_attributes:
            user = User(
                sam_accout_name=user_attributes.get('sAMAccountName'),
                user_principal_name=user_attributes.get('userPrincipalName'),
                mail=user_attributes.get('mail'),
                display_name=user_attributes.get('displayName'),
                directory=new_dir,
            )

            if self.password is not None:
                user.password = get_password_hash(
                    self.password.get_secret_value())

            items_to_add.append(user)
            user.groups.extend(parent_groups)

        elif 'group' in self.attr_names.get('objectClass', []):
            group = Group(directory=new_dir)
            items_to_add.append(group)
            group.parent_groups.extend(parent_groups)

        async with session.begin_nested():
            try:
                new_dir.depth = len(path.path)
                items_to_add.extend([new_dir, path] + attributes)

                session.add_all(items_to_add)

                if has_no_parent:
                    new_dir.paths.append(path)
                else:
                    path.directories.extend(
                        [p.endpoint for p in parent.paths + [path]])
                await session.commit()
            except IntegrityError:
                await session.rollback()
                yield AddResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
                return

        yield AddResponse(result_code=LDAPCodes.SUCCESS)
