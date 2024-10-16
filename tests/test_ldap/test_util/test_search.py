"""Test search with ldaputil.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from ipaddress import IPv4Address

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import Settings
from ldap_protocol.access_policy import create_access_policy
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.ldap_requests import SearchRequest
from ldap_protocol.ldap_responses import SearchResultEntry
from ldap_protocol.utils.queries import (
    get_group,
    get_groups,
    is_user_group_valid,
)
from models import User
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap_search(settings: Settings, creds: TestCreds) -> None:
    """Test ldapsearch on server."""
    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-x', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
        '-D', creds.un,
        '-w', creds.pw,
        '-b', 'dc=md,dc=test', 'objectclass=*',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split('\n')
    result = await proc.wait()

    assert result == 0
    assert "dn: cn=groups,dc=md,dc=test" in data
    assert "dn: ou=users,dc=md,dc=test" in data
    assert "dn: cn=user0,ou=users,dc=md,dc=test" in data


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
async def test_bind_policy(
    session: AsyncSession,
    settings: Settings,
    creds: TestCreds,
    ldap_session: LDAPSession,
) -> None:
    """Bind with policy."""
    policy = await ldap_session._get_policy(IPv4Address('127.0.0.1'), session)
    assert policy

    group_dir = await get_group(
        'cn=domain admins,cn=groups,dc=md,dc=test', session)
    policy.groups.append(group_dir.group)
    await session.commit()

    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
        '-D', creds.un, '-x', '-w', creds.pw)

    result = await proc.wait()
    assert result == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
async def test_bind_policy_missing_group(
        session: AsyncSession,
        ldap_session: LDAPSession,
        settings: Settings,
        creds: TestCreds) -> None:
    """Bind policy fail."""
    policy = await ldap_session._get_policy(IPv4Address('127.0.0.1'), session)

    assert policy

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
        '-vvv', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
        '-D', creds.un, '-x', '-w', creds.pw)

    result = await proc.wait()
    assert result == 49


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap_bind(settings: Settings, creds: TestCreds) -> None:
    """Test ldapsearch on server."""
    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-x', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
        '-D', creds.un,
        '-w', creds.pw,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    result = await proc.wait()
    assert result == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_bvalue_in_search_request(
    session: AsyncSession,
    ldap_bound_session: LDAPSession,
    settings: Settings,
) -> None:
    """Test SearchRequest with bytes data."""
    request = SearchRequest(
        base_object="cn=user0,ou=users,dc=md,dc=test",
        scope=0,
        deref_aliases=0,
        size_limit=0,
        time_limit=0,
        types_only=False,
        filter=ASN1Row(class_id=128, tag_id=7, value="objectClass"),
        attributes=["*"],
    )

    result: SearchResultEntry = await anext(request.handle(
        session, ldap_bound_session, settings))  # type: ignore

    assert result

    for attr in result.partial_attributes:
        if attr.type == 'attr_with_bvalue':
            assert isinstance(attr.vals[0], bytes)


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap_search_access_control_denied(
    settings: Settings,
    creds: TestCreds,
    session: AsyncSession,
) -> None:
    """Test ldapsearch on server.

    Default user can read only himself.
    """
    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-x', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
        '-D', 'user_non_admin',
        '-w', creds.pw,
        '-b', 'dc=md,dc=test', 'objectclass=*',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split('\n')
    result = await proc.wait()

    dn_list = [d for d in data if d.startswith('dn:')]

    assert result == 0
    assert dn_list == ["dn: cn=user_non_admin,ou=users,dc=md,dc=test"]

    await create_access_policy(
        name='Groups Read Access Policy',
        can_add=False,
        can_modify=False,
        can_read=True,
        can_delete=False,
        grant_dn="cn=groups,dc=md,dc=test",
        groups=["cn=domain users,cn=groups,dc=md,dc=test"],
        session=session,
    )
    await session.commit()

    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-x', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
        '-D', 'user_non_admin',
        '-w', creds.pw,
        '-b', 'dc=md,dc=test', 'objectclass=*',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split('\n')
    result = await proc.wait()

    dn_list = [d for d in data if d.startswith('dn:')]

    assert result == 0
    assert sorted(dn_list) == sorted([
        'dn: cn=groups,dc=md,dc=test',
        'dn: cn=domain admins,cn=groups,dc=md,dc=test',
        'dn: cn=developers,cn=groups,dc=md,dc=test',
        'dn: cn=domain users,cn=groups,dc=md,dc=test',
        'dn: cn=user_non_admin,ou=users,dc=md,dc=test',
    ])
