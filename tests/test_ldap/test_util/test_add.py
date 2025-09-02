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
from enums import AceType, RoleScope
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.ldap_requests.contexts import LDAPAddRequestContext
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.dataclasses import AccessControlEntryDTO, RoleDTO
from ldap_protocol.roles.role_dao import RoleDAO
from ldap_protocol.utils.queries import get_search_path
from models import Directory, Group, User, queryable_attr as qa
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
            ),
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapadd",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            user["sam_account_name"],
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
        .options(subqueryload(qa(Directory.attributes)))
        .filter_by(path=search_path)
    )
    new_dir = (await session.scalars(new_dir_query)).one()

    assert new_dir.name == "test"

    attributes = defaultdict(list)

    for attr in new_dir.attributes:
        attributes[attr.name].append(attr.value)

    assert attributes["objectClass"] == ["organization", "top"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_add_duplicate_with_spaces(
    session: AsyncSession,
    settings: Settings,
    user: dict,
) -> None:
    """Test ldapadd on server."""
    dn = "cn=test,dc=md,dc=test"
    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {dn}\n"
                "name: test\n"
                "cn: test\n"
                "objectClass: organization\n"
                "objectClass: top\n"
                "memberOf: cn=domain admins,cn=groups,dc=md,dc=test\n"
            ),
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapadd",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            user["sam_account_name"],
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

    search_path = get_search_path(dn)
    new_dir_query = (
        select(Directory)
        .options(subqueryload(qa(Directory.attributes)))
        .filter_by(path=search_path)
    )
    new_dir = (await session.scalars(new_dir_query)).one()

    assert new_dir.name == "test"

    new_dn = "cn=  test,dc=md,dc=test"
    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {new_dn}\n"
                "name: test\n"
                "cn: test\n"
                "objectClass: organization\n"
                "objectClass: top\n"
                "memberOf: cn=domain admins,cn=groups,dc=md,dc=test\n"
            ),
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapadd",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            user["sam_account_name"],
            "-x",
            "-w",
            user["password"],
            "-f",
            file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        result = await proc.wait()

    assert result == 68


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
            user["sam_account_name"],
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
        selectinload(qa(Directory.user))
        .selectinload(qa(User.groups))
        .selectinload(qa(Group.directory))
    )

    new_dir_query = (
        select(Directory)
        .options(subqueryload(qa(Directory.attributes)), membership)
        .filter_by(path=user_search_path)
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
            ),
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapadd",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            user["sam_account_name"],
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
        selectinload(qa(Directory.group))
        .selectinload(qa(Group.parent_groups))
        .selectinload(qa(Group.directory))
    )

    new_dir_query = (
        select(Directory)
        .options(membership)
        .filter_by(path=child_group_search_path)
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
    ldap_bound_session: LDAPSession,
    ctx_add: LDAPAddRequestContext,
) -> None:
    """Test AddRequest with bytes data."""
    ctx_add.ldap_session = ldap_bound_session
    request = AddRequest(
        entry="cn=test123,dc=md,dc=test",
        attributes=[{"type": "objectClass", "vals": [b"container"]}],
        password=None,
    )
    result = await anext(request.handle(ctx_add))
    assert result.result_code == LDAPCodes.SUCCESS


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_add_access_control(
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
    access_control_entry_dao: AccessControlEntryDAO,
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
                ),
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

    await role_dao.create(
        dto=RoleDTO(
            name="Add Role",
            creator_upn=None,
            is_system=False,
            groups=["cn=domain users,cn=groups," + base_dn],
        ),
    )

    assert await try_add() == LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS

    role_id = role_dao.get_last_id()

    add_ace = AccessControlEntryDTO(
        role_id=role_id,
        ace_type=AceType.CREATE_CHILD,
        scope=RoleScope.WHOLE_SUBTREE,
        base_dn=base_dn,
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    read_ace = AccessControlEntryDTO(
        role_id=role_id,
        ace_type=AceType.READ,
        scope=RoleScope.WHOLE_SUBTREE,
        base_dn=base_dn,
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    await access_control_entry_dao.create_bulk([add_ace, read_ace])

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


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_user_add_with_duplicate_groups(
    session: AsyncSession,
    settings: Settings,
    user: dict,
) -> None:
    """Duplicate memberOf yields single membership."""
    user_dn = "cn=dup,dc=md,dc=test"
    group_dn = "cn=domain admins,cn=groups,dc=md,dc=test"

    with tempfile.NamedTemporaryFile("w") as file:
        ldif = [
            f"dn: {user_dn}",
            "name: dup",
            "cn: dup",
            "userPrincipalName: dup",
            "sAMAccountName: dup",
            "objectClass: inetOrgPerson",
            "objectClass: organizationalPerson",
            "objectClass: user",
            "objectClass: person",
            "objectClass: posixAccount",
            "objectClass: top",
        ] + [f"memberOf: {group_dn}" for _ in range(5)]

        file.write("\n".join(ldif) + "\n")
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapadd",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            user["sam_account_name"],
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

    user_search_path = get_search_path(user_dn)
    user_row = await session.scalar(
        select(User)
        .join(qa(User.directory))
        .filter_by(path=user_search_path)
        .options(
            selectinload(qa(User.groups)).selectinload(qa(Group.directory)),
        ),
    )
    assert user_row
    groups = [g.directory.path_dn for g in user_row.groups]
    assert groups.count(group_dn) == 1
