"""Test modify protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import tempfile
from collections import defaultdict

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload, subqueryload

from config import Settings
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.roles.role_dao import AccessControlEntrySchema, RoleDAO
from ldap_protocol.utils.queries import get_search_path
from models import AceType, Directory, Group, RoleScope
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_base_modify(
    session: AsyncSession,
    settings: Settings,
    user: dict,
) -> None:
    """Test ldapmodify on server."""
    dn = "cn=user0,ou=users,dc=md,dc=test"
    query = (
        select(Directory)
        .options(
            subqueryload(Directory.attributes),
            joinedload(Directory.user),
        )
        .filter(Directory.path == get_search_path(dn))
    )

    directory = (await session.scalars(query)).one()

    assert directory.user.mail == "user0@mail.com"

    attributes = defaultdict(list)

    for attr in directory.attributes:
        attributes[attr.name].append(attr.value)

    assert "user" in attributes["objectClass"]
    assert attributes["posixEmail"] == ["abctest@mail.com"]

    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {dn}\n"
                "changetype: modify\n"
                "replace: mail\n"
                "mail: modme@student.of.life.edu\n"
                "-\n"
                "add: title\n"
                "title: Grand Poobah\n"
                "title: Grand Poobah1\n"
                "title: Grand Poobah2\n"
                "title: Grand Poobah3\n"
                "-\n"
                "add: jpegPhoto\n"
                "jpegPhoto: modme.jpeg\n"
                "-\n"
                "delete: posixEmail\n"
                "-\n"
            )
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapmodify",
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
    session.expire_all()
    directory = (await session.scalars(query)).one()

    attributes = defaultdict(list)

    for attr in directory.attributes:
        attributes[attr.name].append(attr.value)

    assert set(attributes["objectClass"]) == {
        "top",
        "person",
        "organizationalPerson",
        "posixAccount",
        "inetOrgPerson",
        "user",
        "shadowAccount",
    }
    assert attributes["title"] == [
        "Grand Poobah",
        "Grand Poobah1",
        "Grand Poobah2",
        "Grand Poobah3",
    ]
    assert attributes["jpegPhoto"] == ["modme.jpeg"]
    assert directory.user.mail == "modme@student.of.life.edu"

    assert "posixEmail" not in attributes


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_membersip_user_delete(
    session: AsyncSession,
    settings: Settings,
    user: dict,
) -> None:
    """Test ldapmodify on server."""
    dn = "cn=user0,ou=users,dc=md,dc=test"
    query = (
        select(Directory)
        .options(selectinload(Directory.groups))
        .filter(Directory.path == get_search_path(dn))
    )

    directory = (await session.scalars(query)).one()

    assert directory.groups

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((f"dn: {dn}\nchangetype: modify\ndelete: memberOf\n-\n"))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapmodify",
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

    session.expire_all()
    directory = (await session.scalars(query)).one()
    assert not directory.groups


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_membersip_user_add(
    session: AsyncSession,
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Test ldapmodify on server."""
    dn = "cn=user_non_admin,ou=users,dc=md,dc=test"
    query = (
        select(Directory)
        .options(selectinload(Directory.groups).selectinload(Group.directory))
        .filter(Directory.path == get_search_path(dn))
    )

    directory = (await session.scalars(query)).one()

    directory.groups.clear()
    await session.commit()

    assert not directory.groups

    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {dn}\n"
                "changetype: modify\n"
                "add: memberOf\n"
                "memberOf: cn=domain admins,cn=groups,dc=md,dc=test\n"
                "-\n"
            )
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapmodify",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            creds.un,
            "-x",
            "-w",
            creds.pw,
            "-f",
            file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        result = await proc.wait()

    session.expire_all()

    assert result == 0
    directory = (await session.scalars(query)).one()
    assert directory.groups


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_membersip_user_replace(
    session: AsyncSession,
    settings: Settings,
    user: dict,
) -> None:
    """Test ldapmodify on server."""
    dn = "cn=user0,ou=users,dc=md,dc=test"
    query = (
        select(Directory)
        .options(selectinload(Directory.groups))
        .filter(Directory.path == get_search_path(dn))
    )
    directory = (await session.scalars(query)).one()

    assert directory.groups

    new_group_dn = "cn=twisted,cn=groups,dc=md,dc=test\n"

    # add new group
    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {new_group_dn}"
                "name: twisted\n"
                "cn: twisted\n"
                "objectClass: group\n"
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

    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {dn}\n"
                "changetype: modify\n"
                "replace: memberOf\n"
                "memberOf: cn=twisted,cn=groups,dc=md,dc=test\n"
                "-\n"
            )
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapmodify",
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
    session.expire_all()

    directory = (await session.scalars(query)).one()
    assert directory.groups


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_membersip_grp_replace(
    session: AsyncSession,
    settings: Settings,
    user: dict,
) -> None:
    """Test ldapmodify on server."""
    dn = "cn=domain admins,cn=groups,dc=md,dc=test"

    query = (
        select(Directory)
        .options(
            selectinload(Directory.group)
            .selectinload(Group.parent_groups)
            .selectinload(Group.directory)
        )
        .filter(Directory.path == get_search_path(dn))
    )

    directory = await session.scalar(query)

    assert directory
    assert not directory.group.parent_groups

    # add new group
    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                "dn: cn=twisted1,cn=groups,dc=md,dc=test\n"
                "name: twisted\n"
                "cn: twisted\n"
                "objectClass: group\n"
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

    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {dn}\n"
                "changetype: modify\n"
                "replace: memberOf\n"
                "memberOf: cn=twisted1,cn=groups,dc=md,dc=test\n"
                "-\n"
            )
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapmodify",
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

    session.expire_all()
    directory = await session.scalar(query)
    assert directory
    assert directory.group.parent_groups[0].directory.name == "twisted1"


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_modify_dn(
    session: AsyncSession,
    settings: Settings,
    user: dict,
) -> None:
    """Test ldapmodify on server."""
    dn = "cn=user0,ou=users,dc=md,dc=test"

    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {dn}\n"
                "changetype: modrdn\n"
                "newrdn: cn=user2\n"
                "deleteoldrdn: 1\n"
                "newsuperior: ou=users,dc=md,dc=test\n"
            )
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapmodify",
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

        res = await proc.wait()
        assert res == 0

    assert await session.scalar(
        select(Directory)
        .filter(
            Directory.path == ["dc=test", "dc=md", "ou=users", "cn=user2"],
            Directory.entity_type_id.isnot(None),
        )
    )  # fmt: skip


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("_force_override_tls")
async def test_ldap_modify_password_change(
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Test ldapmodify on server."""
    dn = "cn=user0,ou=users,dc=md,dc=test"
    new_password = "Password12345"  # noqa

    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {dn}\n"
                "changetype: modify\n"
                "replace: userPassword\n"
                f"userPassword: {new_password}\n"
                "-\n"
            )
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapmodify",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            creds.un,
            "-x",
            "-w",
            creds.pw,
            "-f",
            file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        result = await proc.wait()

    assert result == 0

    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        creds.un,
        "-x",
        "-w",
        new_password,
    )

    result = await proc.wait()
    assert result == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_ldap_modify_with_ap(
    session: AsyncSession,
    settings: Settings,
    creds: TestCreds,
    role_dao: RoleDAO,
) -> None:
    """Test ldapmodify on server."""
    dn = "ou=users,dc=md,dc=test"
    base_dn = "dc=md,dc=test"
    search_path = get_search_path(dn)

    query = (
        select(Directory)
        .options(
            subqueryload(Directory.attributes),
            joinedload(Directory.user),
        )
        .filter(Directory.path == search_path)
    )

    directory = await session.scalar(query)

    async def try_modify() -> int:
        with tempfile.NamedTemporaryFile("w") as file:
            file.write(
                (
                    f"dn: {dn}\n"
                    "changetype: modify\n"
                    "replace: mail\n"
                    "mail: modme@student.of.life.edu\n"
                    "-\n"
                    "add: title\n"
                    "title: Grand Poobah\n"
                    "title: Grand Poobah1\n"
                    "title: Grand Poobah2\n"
                    "title: Grand Poobah3\n"
                    "-\n"
                    "add: jpegPhoto\n"
                    "jpegPhoto: modme.jpeg\n"
                    "-\n"
                    "delete: posixEmail\n"
                    "-\n"
                )
            )
            file.seek(0)
            proc = await asyncio.create_subprocess_exec(
                "ldapmodify",
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

    assert await try_modify() == LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS

    modify_role = await role_dao.create_role(
        role_name="Modify Role",
        creator_upn=None,
        is_system=False,
        groups_dn=["cn=domain users,cn=groups," + base_dn],
    )

    modify_ace = AccessControlEntrySchema(
        ace_type=AceType.WRITE,
        scope=RoleScope.WHOLE_SUBTREE,
        base_dn=dn,
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    await role_dao.add_access_control_entries(
        role_id=modify_role.id,
        access_control_entries=[modify_ace],
    )

    assert await try_modify() == LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS

    delete_ace = AccessControlEntrySchema(
        ace_type=AceType.DELETE,
        scope=RoleScope.WHOLE_SUBTREE,
        base_dn=dn,
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    await role_dao.add_access_control_entries(
        role_id=modify_role.id,
        access_control_entries=[delete_ace],
    )

    assert await try_modify() == LDAPCodes.SUCCESS

    session.expire_all()
    directory = await session.scalar(query)
    assert directory

    attributes = defaultdict(list)

    for attr in directory.attributes:
        attributes[attr.name].append(attr.value)

    assert attributes["objectClass"] == [
        "top",
        "container",
        "organizationalUnit",
    ]
    assert attributes["title"] == [
        "Grand Poobah",
        "Grand Poobah1",
        "Grand Poobah2",
        "Grand Poobah3",
    ]
    assert attributes["jpegPhoto"] == ["modme.jpeg"]
    assert directory.user.mail == "modme@student.of.life.edu"

    assert "posixEmail" not in attributes
