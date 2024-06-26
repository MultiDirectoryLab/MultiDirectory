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

from app.config import Settings
from app.ldap_protocol.dialogue import LDAPCodes, Session
from app.ldap_protocol.ldap_requests import AddRequest
from app.models.ldap3 import Directory, Group, Path, User


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap_root_add(
        session: AsyncSession, settings: Settings, user: dict) -> None:
    """Test ldapadd on server."""
    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            "dn: cn=test,dc=md,dc=test\n"
            "name: test\n"
            "cn: test\n"
            "objectClass: organization\n"
            "objectClass: top\n"
            "memberOf: cn=domain admins,cn=groups,dc=md,dc=test\n"
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

    query = select(Directory)\
        .options(subqueryload(Directory.attributes))\
        .join(Directory.path).filter(Path.path == ["cn=test"])
    new_dir = await session.scalar(query)

    assert new_dir.name == "test"

    attributes = defaultdict(list)

    for attr in new_dir.attributes:
        attributes[attr.name].append(attr.value)

    assert attributes['objectClass'] == ['organization', 'top']


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap_user_add_with_group(
        session: AsyncSession, settings: Settings, user: dict) -> None:
    """Test ldapadd on server."""
    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            "dn: cn=test,dc=md,dc=test\n"
            "name: test\n"
            "cn: test\n"
            "userPrincipalName: test\n"
            "sAMAccountName: test\n"
            "objectClass: organizationalPerson\n"
            "objectClass: user\n"
            "objectClass: person\n"
            "objectClass: posixAccount\n"
            "objectClass: top\n"
            "memberOf: cn=domain admins,cn=groups,dc=md,dc=test\n",
        )
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

    membership = selectinload(Directory.user).selectinload(
        User.groups).selectinload(
            Group.directory).selectinload(Directory.path)

    query = select(Directory)\
        .options(subqueryload(Directory.attributes), membership)\
        .join(Directory.path).filter(Path.path == ["cn=test"])

    new_dir = await session.scalar(query)

    assert new_dir.name == "test"

    group = new_dir.user.groups[0]

    assert sorted(group.directory.path.path) == sorted(
        ['cn=domain admins', 'cn=groups'])


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.filterwarnings("ignore::sqlalchemy.exc.SAWarning")
async def test_ldap_user_add_group_with_group(
        session: AsyncSession, settings: Settings, user: dict) -> None:
    """Test ldapadd on server."""
    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            "dn: cn=twisted,cn=groups,dc=md,dc=test\n"
            "name: twisted\n"
            "cn: twisted\n"
            "objectClass: group\n"
            "objectClass: top\n"
            "memberOf: cn=domain admins,cn=groups,dc=md,dc=test\n"
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

    membership = selectinload(Directory.group).selectinload(
        Group.parent_groups).selectinload(
            Group.directory).selectinload(Directory.path)

    query = select(Directory)\
        .options(membership)\
        .join(Directory.path).filter(Path.path == ["cn=groups", "cn=twisted"])

    new_dir = await session.scalar(query)

    assert new_dir.name == "twisted"

    group = new_dir.group.parent_groups[0]

    assert sorted(group.directory.path.path) == sorted(
        ['cn=domain admins', 'cn=groups'])


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_add_bvalue_attr(session: AsyncSession, ldap_session: Session) \
        -> None:
    """Test AddRequest with bytes data."""
    ldap_session._user = True

    request = AddRequest(
        entry="cn=test123,dc=md,dc=test",
        attributes=[{"type": "objectclass", "vals": [b"test"]}],
        password=None,
    )
    result = await anext(request.handle(ldap_session, session))
    assert result.result_code == LDAPCodes.SUCCESS
