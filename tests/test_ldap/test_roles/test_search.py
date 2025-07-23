"""End-To-End tests for Search request with role model.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio

import pytest
import pytest_asyncio
from enums import AceType, RoleScope

from config import Settings
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.roles.role_dao import AccessControlEntrySchema, RoleDAO
from models import Role
from tests.conftest import TestCreds

BASE_DN = "dc=md,dc=test"


@pytest_asyncio.fixture(scope="function")
async def custom_role(role_dao: RoleDAO) -> Role:
    """Fixture to create a custom role for testing."""
    return await role_dao.create_role(
        role_name="Custom Role",
        creator_upn=None,
        is_system=False,
        groups_dn=["cn=domain users,cn=groups,dc=md,dc=test"],
    )


async def run_ldap_search(
    settings: Settings,
    creds: TestCreds,
    search_base: str = "dc=md,dc=test",
) -> tuple[int, list[str]]:
    """Run ldapsearch command and return the result."""
    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-x",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        "user_non_admin",
        "-w",
        creds.pw,
        "-b",
        search_base,
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    return result, data


async def perform_ldap_search_and_validate(
    settings: Settings,
    creds: TestCreds,
    search_base: str,
    expected_dn: list[str],
    expected_attrs_present: list[str],
    expected_attrs_absent: list[str],
) -> None:
    """Perform LDAP search and validate results."""
    result, data = await run_ldap_search(
        settings,
        creds,
        search_base=search_base,
    )

    dn_list = [d for d in data if d.startswith("dn:")]

    assert result == 0
    assert sorted(dn_list) == sorted(expected_dn)

    for expected in expected_attrs_present:
        assert expected in data

    for unexpected in expected_attrs_absent:
        assert unexpected not in data


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
        scope=RoleScope.SELF,
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
        scope=RoleScope.SELF,
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
            scope=RoleScope.SELF,
            base_dn="cn=user0,ou=users,dc=md,dc=test",
            attribute_type_id=None,
            entity_type_id=user_entity_type.id,
            is_allow=True,
        ),
        AccessControlEntrySchema(
            ace_type=AceType.READ,
            scope=RoleScope.SELF,
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
            scope=RoleScope.SELF,
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
            scope=RoleScope.SELF,
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
