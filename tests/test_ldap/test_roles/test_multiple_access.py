"""End-To-End multiple  for role model.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from collections import defaultdict

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, subqueryload

from config import Settings
from enums import AceType, RoleScope
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.roles.role_dao import AccessControlEntrySchema, RoleDAO
from ldap_protocol.utils.queries import get_search_path
from models import Directory, Role
from tests.conftest import TestCreds

from .conftest import perform_ldap_search_and_validate, run_ldap_modify


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_multiple_access(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
    entity_type_dao: EntityTypeDAO,
    attribute_type_dao: AttributeTypeDAO,
    session: AsyncSession,
    custom_role: Role,
) -> None:
    """Test multiple access control entries in a role."""
    user_entity_type = await entity_type_dao.get_one_by_name("User")
    assert user_entity_type

    posix_email_attr = await attribute_type_dao.get_one_by_name("posixEmail")
    assert posix_email_attr

    user_principal_name = await attribute_type_dao.get_one_by_name(
        "userPrincipalName"
    )
    assert user_principal_name

    user_account_control_attr = await attribute_type_dao.get_one_by_name(
        "userAccountControl"
    )
    assert user_account_control_attr

    aces = [
        AccessControlEntrySchema(
            ace_type=AceType.READ,
            scope=RoleScope.WHOLE_SUBTREE,
            base_dn="ou=russia,ou=users,dc=md,dc=test",
            entity_type_id=user_entity_type.id,
            attribute_type_id=user_account_control_attr.id,
            is_allow=True,
        ),
        AccessControlEntrySchema(
            ace_type=AceType.READ,
            scope=RoleScope.WHOLE_SUBTREE,
            base_dn="ou=russia,ou=users,dc=md,dc=test",
            entity_type_id=user_entity_type.id,
            attribute_type_id=user_principal_name.id,
            is_allow=True,
        ),
        AccessControlEntrySchema(
            ace_type=AceType.WRITE,
            scope=RoleScope.WHOLE_SUBTREE,
            base_dn="ou=russia,ou=users,dc=md,dc=test",
            entity_type_id=user_entity_type.id,
            attribute_type_id=posix_email_attr.id,
            is_allow=True,
        ),
        AccessControlEntrySchema(
            ace_type=AceType.DELETE,
            scope=RoleScope.WHOLE_SUBTREE,
            base_dn="ou=russia,ou=users,dc=md,dc=test",
            entity_type_id=user_entity_type.id,
            attribute_type_id=posix_email_attr.id,
            is_allow=True,
        ),
    ]

    await role_dao.add_access_control_entries(
        role_id=custom_role.id,
        access_control_entries=aces,
    )

    await perform_ldap_search_and_validate(
        settings=settings,
        creds=creds,
        search_base="ou=russia,ou=users,dc=md,dc=test",
        expected_dn=[
            "dn: cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test",
        ],
        expected_attrs_present=[
            "userAccountControl: 512",
            "userPrincipalName: user1",
        ],
        expected_attrs_absent=["posixEmail: user1@mail.com"]
    )

    user_dn = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"

    query = (
        select(Directory)
        .options(
            subqueryload(Directory.attributes),
            joinedload(Directory.user),
        )
        .filter(Directory.path == get_search_path(user_dn))
    )

    directory = (await session.scalars(query)).one()
    attributes = defaultdict(list)
    for attr in directory.attributes:
        attributes[attr.name].append(attr.value)

    assert attributes["posixEmail"] == ["user1@mail.com"]

    session.expire_all()
    result = await run_ldap_modify(
        settings=settings,
        creds=creds,
        dn=user_dn,
        attribute="posixEmail",
        value="modme@student.of.life.edu"
    )
    assert result == 0
    session.expire_all()

    directory = (await session.scalars(query)).one()
    attributes = defaultdict(list)
    for attr in directory.attributes:
        attributes[attr.name].append(attr.value)

    assert "posixEmail" in attributes
    assert attributes["posixEmail"] == ["modme@student.of.life.edu"]

    session.expire_all()
    result = await run_ldap_modify(
        settings=settings,
        creds=creds,
        dn=user_dn,
        attribute="userPrincipalName",
        value="v"
    )
    assert result == 50  # Expecting an error due to write access not allowed
