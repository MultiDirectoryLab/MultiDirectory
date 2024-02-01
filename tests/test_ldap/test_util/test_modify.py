"""Test modify protocol."""

import asyncio
import tempfile
from collections import defaultdict

import pytest
from sqlalchemy import select
from sqlalchemy.orm import joinedload, selectinload, subqueryload

from app.extra import TEST_DATA
from app.models.ldap3 import Directory, Group, Path, User


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap_base_modify(session, settings):
    """Test ldapmodify on server."""
    user = TEST_DATA[1]['children'][0]['organizationalPerson']

    dn = "cn=user0,ou=users,dc=multidurectory,dc=test"

    query = select(Directory)\
        .options(
            subqueryload(Directory.attributes),
            joinedload(Directory.user))\
        .join(Directory.path).filter(Path.path == ["ou=users", "cn=user0"])

    directory = await session.scalar(query)
    assert directory.user.mail == "user0@mail.com"

    attributes = defaultdict(list)

    for attr in directory.attributes:
        attributes[attr.name].append(attr.value)

    assert 'user' in attributes['objectClass']
    assert attributes['posixEmail'] == ["abctest@mail.com"]

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
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
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapmodify',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        result = await proc.wait()

    assert result == 0
    await session.refresh(directory)

    attributes = defaultdict(list)

    for attr in directory.attributes:
        attributes[attr.name].append(attr.value)

    assert attributes['objectClass'] == [
        'top', 'person',
        'organizationalPerson', 'posixAccount', 'user']
    assert attributes['title'] == [
        "Grand Poobah", "Grand Poobah1",
        "Grand Poobah2", "Grand Poobah3",
    ]
    assert attributes['jpegPhoto'] == ['modme.jpeg']
    assert directory.user.mail == "modme@student.of.life.edu"

    assert 'posixEmail' not in attributes


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap_membersip_user_delete(session, settings):
    """Test ldapmodify on server."""
    user = TEST_DATA[1]['children'][0]['organizationalPerson']

    dn = "cn=user0,ou=users,dc=multidurectory,dc=test"

    membership = selectinload(Directory.user).selectinload(
        User.groups).selectinload(
            Group.directory).selectinload(Directory.path)

    query = select(Directory)\
        .options(
            subqueryload(Directory.attributes),
            joinedload(Directory.user), membership)\
        .join(Directory.path).filter(Path.path == ["ou=users", "cn=user0"])

    directory = await session.scalar(query)

    assert directory.user.groups

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {dn}\n"
            "changetype: modify\n"
            "delete: memberOf\n"
            "-\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapmodify',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        result = await proc.wait()

    assert result == 0
    await session.refresh(directory)
    assert not directory.user.groups


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap_membersip_user_add(session, settings):
    """Test ldapmodify on server."""
    user = TEST_DATA[1]['children'][0]['organizationalPerson']

    dn = "cn=user0,ou=users,dc=multidurectory,dc=test"

    membership = selectinload(Directory.user).selectinload(
        User.groups).selectinload(
            Group.directory).selectinload(Directory.path)

    query = select(Directory)\
        .options(
            subqueryload(Directory.attributes),
            joinedload(Directory.user), membership)\
        .join(Directory.path).filter(Path.path == ["ou=users", "cn=user0"])

    directory = await session.scalar(query)

    directory.user.groups.clear()
    await session.commit()

    assert not directory.user.groups

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {dn}\n"
            "changetype: modify\n"
            "add: memberOf\n"
            "memberOf: cn=domain admins,cn=groups,dc=multidurectory,dc=test\n"
            "-\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapmodify',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        result = await proc.wait()

    assert result == 0
    await session.refresh(directory)
    assert directory.user.groups


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap_membersip_user_replace(session, settings):
    """Test ldapmodify on server."""
    user = TEST_DATA[1]['children'][0]['organizationalPerson']

    dn = "cn=user0,ou=users,dc=multidurectory,dc=test"

    membership = selectinload(Directory.user).selectinload(
        User.groups).selectinload(
            Group.directory).selectinload(Directory.path)

    query = select(Directory)\
        .options(
            subqueryload(Directory.attributes),
            joinedload(Directory.user), membership)\
        .join(Directory.path).filter(Path.path == ["ou=users", "cn=user0"])

    directory = await session.scalar(query)

    assert directory.user.groups

    new_group_dn = "cn=twisted,cn=groups,dc=multidurectory,dc=test\n"

    # add new group
    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {new_group_dn}"
            "name: twisted\n"
            "cn: twisted\n"
            "objectClass: group\n"
            "objectClass: top\n"
            "memberOf: cn=domain admins,cn=groups,dc=multidurectory,dc=test\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapadd',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        result = await proc.wait()

        assert result == 0

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {dn}\n"
            "changetype: modify\n"
            "replace: memberOf\n"
            "memberOf: cn=twisted,cn=groups,dc=multidurectory,dc=test\n"
            "-\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapmodify',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        result = await proc.wait()

    assert result == 0
    await session.refresh(directory)
    assert directory.user.groups


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap_membersip_grp_replace(session, settings):
    """Test ldapmodify on server."""
    user = TEST_DATA[1]['children'][0]['organizationalPerson']

    dn = "cn=domain admins,cn=groups,dc=multidurectory,dc=test"

    membership = selectinload(Directory.group).selectinload(
        Group.parent_groups).selectinload(
            Group.directory).selectinload(Directory.path)

    query = select(Directory)\
        .options(
            subqueryload(Directory.attributes),
            joinedload(Directory.user), membership)\
        .join(Directory.path)\
        .filter(Path.path == ["cn=groups", "cn=domain admins"])

    directory = await session.scalar(query)

    assert not directory.group.parent_groups

    # add new group
    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            "dn: cn=twisted1,cn=groups,dc=multidurectory,dc=test\n"
            "name: twisted\n"
            "cn: twisted\n"
            "objectClass: group\n"
            "objectClass: top\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapadd',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        result = await proc.wait()

        assert result == 0

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {dn}\n"
            "changetype: modify\n"
            "replace: memberOf\n"
            "memberOf: cn=twisted1,cn=groups,dc=multidurectory,dc=test\n"
            "-\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapmodify',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        result = await proc.wait()

        assert result == 0

    await session.refresh(directory)
    assert directory.group.parent_groups[0].directory.name == "twisted1"


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap_modify_dn(session, settings):
    """Test ldapmodify on server."""
    user = TEST_DATA[1]['children'][0]['organizationalPerson']

    dn = "cn=user0,ou=users,dc=multidurectory,dc=test"

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {dn}\n"
            "changetype: modrdn\n"
            "newrdn: uid=user1\n"
            "deleteoldrdn: 1\n"
            "newsuperior: ou=users,dc=multidurectory,dc=test\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapmodify',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        res = await proc.wait()
        assert res == 0

    query = select(Directory)\
        .join(Directory.path).filter(Path.path == ["ou=users", "uid=user1"])

    assert await session.scalar(query)