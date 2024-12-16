"""Test policy api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from ipaddress import IPv4Address, IPv4Network

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.utils.queries import (
    get_group,
    get_user,
    is_user_group_valid,
)
from models import NetworkPolicy


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_check_policy(
        ldap_session: LDAPSession, session: AsyncSession) -> None:
    """Check policy."""
    policy = await ldap_session._get_policy(IPv4Address("127.0.0.1"), session)
    assert policy
    assert policy.netmasks == [IPv4Network("0.0.0.0/0")]


@pytest.mark.asyncio
async def test_specific_policy_ok(
        ldap_session: LDAPSession, session: AsyncSession) -> None:
    """Test specific ip."""
    session.add(NetworkPolicy(
        name='Local policy',
        netmasks=[IPv4Network('127.100.10.5/32')],
        raw=['127.100.10.5/32'],
        enabled=True,
        priority=1,
        is_http=True,
        is_ldap=True,
        is_kerberos=True,
    ))
    await session.commit()
    policy = await ldap_session._get_policy(
        IPv4Address("127.100.10.5"), session)
    assert policy
    assert policy.netmasks == [IPv4Network("127.100.10.5/32")]
    assert not await ldap_session._get_policy(
        IPv4Address("127.100.10.4"), session)


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('settings')
async def test_check_policy_group(
        ldap_session: LDAPSession,
        session: AsyncSession) -> None:
    """Check policy."""
    user = await get_user(session, "user0")
    assert user

    policy = await ldap_session._get_policy(IPv4Address('127.0.0.1'), session)
    assert policy

    assert await is_user_group_valid(user, policy, session)

    group_dir = await get_group(
        'cn=domain admins,cn=groups,dc=md,dc=test', session)

    policy.groups.append(group_dir.group)
    await session.commit()

    assert await is_user_group_valid(user, policy, session)
