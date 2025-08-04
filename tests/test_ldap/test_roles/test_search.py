"""End-To-End tests for Search request with role model.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest

from config import Settings
from enums import AceType, RoleScope
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.roles.role_dao import AccessControlEntrySchema, RoleDAO
from models import Role
from tests.conftest import TestCreds

from .conftest import perform_ldap_search_and_validate

BASE_DN = "dc=md,dc=test"


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_role_search_1(settings: Settings, creds: TestCreds) -> None:
    """Test 1.

    User without any roles should only see their own entry.
    """
    await perform_ldap_search_and_validate(
        settings=settings,
        creds=creds,
        search_base=BASE_DN,
        expected_dn=["dn: cn=user_non_admin,ou=users,dc=md,dc=test"],
        expected_attrs_present=[],
        expected_attrs_absent=[],
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_role_search_2(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
    custom_role: Role,
) -> None:
    """Test 2.

    User with a custom role should see only the group entry.
    """
    ace = AccessControlEntrySchema(
        ace_type=AceType.READ,
        scope=RoleScope.BASE_OBJECT,
        base_dn="cn=groups,dc=md,dc=test",
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    await role_dao.add_access_control_entries(
        role_id=custom_role.id,
        access_control_entries=[ace],
    )

    await perform_ldap_search_and_validate(
        settings=settings,
        creds=creds,
        search_base=BASE_DN,
        expected_dn=[
            "dn: cn=groups,dc=md,dc=test",
            "dn: cn=user_non_admin,ou=users,dc=md,dc=test",
        ],
        expected_attrs_present=[],
        expected_attrs_absent=[],
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_role_search_3(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
    custom_role: Role,
) -> None:
    """Test 3.

    User with a custom role should see the group and user entries.
    """
    ace = AccessControlEntrySchema(
        ace_type=AceType.READ,
        scope=RoleScope.SINGLE_LEVEL,
        base_dn="dc=md,dc=test",
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    await role_dao.add_access_control_entries(
        role_id=custom_role.id,
        access_control_entries=[ace],
    )

    await perform_ldap_search_and_validate(
        settings=settings,
        creds=creds,
        search_base=BASE_DN,
        expected_dn=[
            "dn: cn=groups,dc=md,dc=test",
            "dn: ou=users,dc=md,dc=test",
            "dn: cn=user_non_admin,ou=users,dc=md,dc=test",
        ],
        expected_attrs_present=[],
        expected_attrs_absent=[],
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_role_search_4(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
    custom_role: Role,
) -> None:
    """Test 4.

    User with a custom role should see all groups and their members.
    """
    ace = AccessControlEntrySchema(
        ace_type=AceType.READ,
        scope=RoleScope.WHOLE_SUBTREE,
        base_dn="cn=groups,dc=md,dc=test",
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    await role_dao.add_access_control_entries(
        role_id=custom_role.id,
        access_control_entries=[ace],
    )

    await perform_ldap_search_and_validate(
        settings=settings,
        creds=creds,
        search_base=BASE_DN,
        expected_dn=[
            "dn: cn=groups,dc=md,dc=test",
            "dn: cn=domain admins,cn=groups,dc=md,dc=test",
            "dn: cn=developers,cn=groups,dc=md,dc=test",
            "dn: cn=domain users,cn=groups,dc=md,dc=test",
            "dn: cn=user_non_admin,ou=users,dc=md,dc=test",
        ],
        expected_attrs_present=[],
        expected_attrs_absent=[],
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_role_search_5(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
    custom_role: Role,
    entity_type_dao: EntityTypeDAO,
) -> None:
    """Test 5.

    User with a custom role should see all Users objects.
    """
    user_entity_type = await entity_type_dao.get_one_by_name("User")
    assert user_entity_type

    ace = AccessControlEntrySchema(
        ace_type=AceType.READ,
        scope=RoleScope.WHOLE_SUBTREE,
        base_dn="dc=md,dc=test",
        attribute_type_id=None,
        entity_type_id=user_entity_type.id,
        is_allow=True,
    )

    await role_dao.add_access_control_entries(
        role_id=custom_role.id,
        access_control_entries=[ace],
    )

    await perform_ldap_search_and_validate(
        settings=settings,
        creds=creds,
        search_base=BASE_DN,
        expected_dn=[
            "dn: cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test",
            "dn: cn=user_non_admin,ou=users,dc=md,dc=test",
            "dn: cn=user_admin,ou=users,dc=md,dc=test",
            "dn: cn=user0,ou=users,dc=md,dc=test",
        ],
        expected_attrs_present=[
            "posixEmail: abctest@mail.com",
            "description: 123 desc",
            "cn: user0",
        ],
        expected_attrs_absent=[],
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_role_search_6(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
    custom_role: Role,
    entity_type_dao: EntityTypeDAO,
    attribute_type_dao: AttributeTypeDAO,
) -> None:
    """Test 6.

    User with a custom role should see only the posixEmail attribute.
    """
    user_entity_type = await entity_type_dao.get_one_by_name("User")
    assert user_entity_type

    posix_email_attr = await attribute_type_dao.get_one_by_name("posixEmail")
    assert posix_email_attr

    ace = AccessControlEntrySchema(
        ace_type=AceType.READ,
        scope=RoleScope.BASE_OBJECT,
        base_dn="cn=user0,ou=users,dc=md,dc=test",
        attribute_type_id=posix_email_attr.id,
        entity_type_id=user_entity_type.id,
        is_allow=True,
    )

    await role_dao.add_access_control_entries(
        role_id=custom_role.id,
        access_control_entries=[ace],
    )

    await perform_ldap_search_and_validate(
        settings=settings,
        creds=creds,
        search_base="cn=user0,ou=users,dc=md,dc=test",
        expected_dn=[
            "dn: cn=user0,ou=users,dc=md,dc=test",
        ],
        expected_attrs_present=[
            "posixEmail: abctest@mail.com",
        ],
        expected_attrs_absent=[
            "description: 123 desc",
            "cn: user0",
        ],
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_role_search_7(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
    custom_role: Role,
    entity_type_dao: EntityTypeDAO,
    attribute_type_dao: AttributeTypeDAO,
) -> None:
    """Test 7.

    User with a custom role should see all attributes except description.
    """
    user_entity_type = await entity_type_dao.get_one_by_name("User")
    assert user_entity_type

    description_attr = await attribute_type_dao.get_one_by_name("description")
    assert description_attr

    aces = [
        AccessControlEntrySchema(
            ace_type=AceType.READ,
            scope=RoleScope.BASE_OBJECT,
            base_dn="cn=user0,ou=users,dc=md,dc=test",
            attribute_type_id=None,
            entity_type_id=user_entity_type.id,
            is_allow=True,
        ),
        AccessControlEntrySchema(
            ace_type=AceType.READ,
            scope=RoleScope.BASE_OBJECT,
            base_dn="cn=user0,ou=users,dc=md,dc=test",
            attribute_type_id=description_attr.id,
            entity_type_id=user_entity_type.id,
            is_allow=False,
        ),
    ]

    await role_dao.add_access_control_entries(
        role_id=custom_role.id,
        access_control_entries=aces,
    )

    await perform_ldap_search_and_validate(
        settings=settings,
        creds=creds,
        search_base="cn=user0,ou=users,dc=md,dc=test",
        expected_dn=[
            "dn: cn=user0,ou=users,dc=md,dc=test",
        ],
        expected_attrs_present=[
            "posixEmail: abctest@mail.com",
            "cn: user0",
        ],
        expected_attrs_absent=[
            "description: 123 desc",
        ],
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_role_search_8(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
    custom_role: Role,
    entity_type_dao: EntityTypeDAO,
    attribute_type_dao: AttributeTypeDAO,
) -> None:
    """Test 8.

    User with a custom role should see only the description attribute.
    """
    user_entity_type = await entity_type_dao.get_one_by_name("User")
    assert user_entity_type

    description_attr = await attribute_type_dao.get_one_by_name("description")
    assert description_attr

    aces = [
        AccessControlEntrySchema(
            ace_type=AceType.READ,
            scope=RoleScope.WHOLE_SUBTREE,
            base_dn="dc=md,dc=test",
            attribute_type_id=None,
            entity_type_id=user_entity_type.id,
            is_allow=False,
        ),
        AccessControlEntrySchema(
            ace_type=AceType.READ,
            scope=RoleScope.BASE_OBJECT,
            base_dn="cn=user0,ou=users,dc=md,dc=test",
            attribute_type_id=description_attr.id,
            entity_type_id=user_entity_type.id,
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
        search_base="cn=user0,ou=users,dc=md,dc=test",
        expected_dn=[
            "dn: cn=user0,ou=users,dc=md,dc=test",
        ],
        expected_attrs_present=[
            "description: 123 desc",
        ],
        expected_attrs_absent=[
            "posixEmail: abctest@mail.com",
            "cn: user0",
        ],
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_role_search_9(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
    custom_role: Role,
    entity_type_dao: EntityTypeDAO,
    attribute_type_dao: AttributeTypeDAO,
) -> None:
    """Test 9.

    User with a custom role should see only the posixEmail attribute.
    """
    user_entity_type = await entity_type_dao.get_one_by_name("User")
    assert user_entity_type

    description_attr = await attribute_type_dao.get_one_by_name("description")
    assert description_attr

    posix_email_attr = await attribute_type_dao.get_one_by_name("posixEmail")
    assert posix_email_attr

    aces = [
        AccessControlEntrySchema(
            ace_type=AceType.READ,
            scope=RoleScope.WHOLE_SUBTREE,
            base_dn="cn=user0,ou=users,dc=md,dc=test",
            attribute_type_id=posix_email_attr.id,
            entity_type_id=user_entity_type.id,
            is_allow=True,
        ),
        AccessControlEntrySchema(
            ace_type=AceType.READ,
            scope=RoleScope.BASE_OBJECT,
            base_dn="cn=user0,ou=users,dc=md,dc=test",
            attribute_type_id=description_attr.id,
            entity_type_id=user_entity_type.id,
            is_allow=False,
        ),
    ]

    await role_dao.add_access_control_entries(
        role_id=custom_role.id,
        access_control_entries=aces,
    )

    await perform_ldap_search_and_validate(
        settings=settings,
        creds=creds,
        search_base="cn=user0,ou=users,dc=md,dc=test",
        expected_dn=[
            "dn: cn=user0,ou=users,dc=md,dc=test",
        ],
        expected_attrs_present=[
            "posixEmail: abctest@mail.com",
        ],
        expected_attrs_absent=[
            "description: 123 desc",
            "cn: user0",
        ],
    )
