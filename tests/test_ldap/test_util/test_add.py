"""Test add protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import tempfile
from collections import defaultdict

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, subqueryload

from config import Settings
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.roles.access_manager import AccessManager
from ldap_protocol.roles.enums import AceType, RoleScope
from ldap_protocol.roles.role_dao import AccessControlEntrySchema, RoleDAO
from ldap_protocol.utils.queries import get_search_path
from models import Directory, Group, User
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_root_add(
    session: AsyncSession,
    settings: Settings,
    user: dict,
) -> None:
    """Test ldapadd on server."""
    dn = "cn=test,dc=md,dc=test"
    search_path = get_search_path(dn)
    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {dn}\n"
                "name: test\n"
                "cn: test\n"
                "objectClass: organization\n"
                "objectClass: top\n"
                "memberOf: cn=domain admins,cn=groups,dc=md,dc=test\n"
            )
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapadd",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            user["sam_accout_name"],
            "-x",
            "-w",
            user["password"],
            "-f",
            file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        result = await proc.wait()

    assert result == 0

    new_dir_query = (
        select(Directory)
        .options(subqueryload(Directory.attributes))
        .filter(Directory.path == search_path)
    )
    new_dir = (await session.scalars(new_dir_query)).one()

    assert new_dir.name == "test"

    attributes = defaultdict(list)

    for attr in new_dir.attributes:
        attributes[attr.name].append(attr.value)

    assert attributes["objectClass"] == ["organization", "top"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_user_add_with_group(
    session: AsyncSession,
    settings: Settings,
    user: dict,
) -> None:
    """Test ldapadd on server."""
    user_dn = "cn=test,dc=md,dc=test"
    user_search_path = get_search_path(user_dn)
    group_dn = "cn=domain admins,cn=groups,dc=md,dc=test"

    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            f"dn: {user_dn}\n"
            "name: test\n"
            "cn: test\n"
            "userPrincipalName: test\n"
            "sAMAccountName: test\n"
            "objectClass: inetOrgPerson\n"
            "objectClass: organizationalPerson\n"
            "objectClass: user\n"
            "objectClass: person\n"
            "objectClass: posixAccount\n"
            "objectClass: top\n"
            f"memberOf: {group_dn}\n",
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapadd",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            user["sam_accout_name"],
            "-x",
            "-w",
            user["password"],
            "-f",
            file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        result = await proc.wait()

    assert result == 0

    membership = (
        selectinload(Directory.user)
        .selectinload(User.groups)
        .selectinload(Group.directory)
    )

    new_dir_query = (
        select(Directory)
        .options(subqueryload(Directory.attributes), membership)
        .filter(Directory.path == user_search_path)
    )
    new_dir = (await session.scalars(new_dir_query)).one()

    assert new_dir.name == "test"

    groups = [group.directory.path_dn for group in new_dir.user.groups]

    assert group_dn in groups


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_user_add_group_with_group(
    session: AsyncSession,
    settings: Settings,
    user: dict,
) -> None:
    """Test ldapadd on server."""
    child_group_dn = "cn=twisted,cn=groups,dc=md,dc=test"
    child_group_search_path = get_search_path(child_group_dn)
    group_dn = "cn=domain admins,cn=groups,dc=md,dc=test"

    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {child_group_dn}\n"
                "name: twisted\n"
                "cn: twisted\n"
                "objectClass: group\n"
                "objectClass: top\n"
                f"memberOf: {group_dn}\n"
            )
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapadd",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            user["sam_accout_name"],
            "-x",
            "-w",
            user["password"],
            "-f",
            file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        result = await proc.wait()

        assert result == 0

    membership = (
        selectinload(Directory.group)
        .selectinload(Group.parent_groups)
        .selectinload(Group.directory)
    )

    new_dir_query = (
        select(Directory)
        .options(membership)
        .filter(Directory.path == child_group_search_path)
    )
    new_dir = (await session.scalars(new_dir_query)).one()

    assert new_dir.name == "twisted"

    groups = [group.directory.path_dn for group in new_dir.group.parent_groups]

    assert group_dn in groups


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("entity_type_dao")
async def test_add_bvalue_attr(
    session: AsyncSession,
    ldap_bound_session: LDAPSession,
    kadmin: AbstractKadmin,
    entity_type_dao: EntityTypeDAO,
    access_manager: AccessManager,
) -> None:
    """Test AddRequest with bytes data."""
    request = AddRequest(
        entry="cn=test123,dc=md,dc=test",
        attributes=[{"type": "objectClass", "vals": [b"container"]}],
        password=None,
    )
    result = await anext(
        request.handle(
            session,
            ldap_bound_session,
            kadmin,
            entity_type_dao,
            access_manager,
        )
    )
    assert result.result_code == LDAPCodes.SUCCESS


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_add_access_control(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
) -> None:
    """Test ldapadd on server."""
    dn = "cn=test,dc=md,dc=test"
    base_dn = "dc=md,dc=test"

    async def try_add() -> int:
        with tempfile.NamedTemporaryFile("w") as file:
            file.write(
                (
                    f"dn: {dn}\n"
                    "name: test\n"
                    "cn: test\n"
                    "objectClass: organization\n"
                    "objectClass: top\n"
                )
            )
            file.seek(0)
            proc = await asyncio.create_subprocess_exec(
                "ldapadd",
                "-vvv",
                "-H",
                f"ldap://{settings.HOST}:{settings.PORT}",
                "-D",
                "user_non_admin",
                "-x",
                "-w",
                creds.pw,
                "-f",
                file.name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            return await proc.wait()

    assert await try_add() == LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS

    add_role = await role_dao.create_role(
        role_name="Add Role",
        creator_upn=None,
        is_system=False,
        groups_dn=["cn=domain users,cn=groups," + base_dn],
    )

    assert await try_add() == LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS

    add_ace = AccessControlEntrySchema(
        ace_type=AceType.CREATE_CHILD,
        scope=RoleScope.WHOLE_SUBTREE,
        base_dn=base_dn,
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    read_ace = AccessControlEntrySchema(
        ace_type=AceType.READ,
        scope=RoleScope.WHOLE_SUBTREE,
        base_dn=base_dn,
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    await role_dao.add_access_control_entries(
        role_id=add_role.id,
        access_control_entries=[add_ace, read_ace],
    )

    assert await try_add() == LDAPCodes.SUCCESS

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
        "dc=md,dc=test",
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    dn_list = [d.removeprefix("dn: ") for d in data if d.startswith("dn:")]

    assert result == 0
    assert dn in dn_list
