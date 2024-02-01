import asyncio
from ipaddress import IPv4Address

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.extra import TEST_DATA
from app.ldap_protocol.utils import get_group, get_groups, is_user_group_valid
from app.models.ldap3 import User


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap_search(settings):
    """Test ldapsearch on server."""
    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D',
        TEST_DATA[1]['children'][0]['organizationalPerson']['sam_accout_name'],
        '-x', '-w',
        TEST_DATA[1]['children'][0]['organizationalPerson']['password'],
        '-b', 'dc=md,dc=test', 'objectclass=*',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    data, _ = await proc.communicate()
    data = data.decode().split('\n')
    result = await proc.wait()

    assert result == 0
    assert "dn: cn=groups,dc=md,dc=test" in data
    assert "dn: ou=users,dc=md,dc=test" in data
    assert "dn: cn=user0,ou=users,dc=md,dc=test" in data


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_bind_policy(handler, session, settings):
    """Bind with policy."""
    un = TEST_DATA[1]['children'][0]['organizationalPerson']['sam_accout_name']
    pw = TEST_DATA[1]['children'][0]['organizationalPerson']['password']

    policy = await handler.get_policy(IPv4Address('127.0.0.1'))
    group_dir = await get_group(
        'cn=domain admins,cn=groups,dc=md,dc=test', session)
    policy.groups.append(group_dir.group)
    await session.commit()

    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D', un, '-x', '-w', pw)

    result = await proc.wait()
    assert result == 0


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_bind_policy_missing_group(handler, session, settings):
    """Bind policy fail."""
    un = TEST_DATA[1]['children'][0]['organizationalPerson']['sam_accout_name']
    pw = TEST_DATA[1]['children'][0]['organizationalPerson']['password']

    policy = await handler.get_policy(IPv4Address('127.0.0.1'))

    user = await session.scalar(
        select(User).filter_by(display_name="user0")
        .options(selectinload(User.groups)))

    policy.groups = await get_groups(
        ['cn=domain admins,cn=groups,dc=md,dc=test'],
        session,
    )
    user.groups.clear()
    await session.commit()

    assert not await is_user_group_valid(user, policy, session)

    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D', un, '-x', '-w', pw)

    result = await proc.wait()
    assert result == 49


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap_bind(settings):
    """Test ldapsearch on server."""
    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D',
        TEST_DATA[1]['children'][0]['organizationalPerson']['sam_accout_name'],
        '-x', '-w',
        TEST_DATA[1]['children'][0]['organizationalPerson']['password'],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    result = await proc.wait()
    assert result == 0
