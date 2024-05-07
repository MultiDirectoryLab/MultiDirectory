"""Test policy api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from ipaddress import IPv4Address, IPv4Network

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.__main__ import PoolClientHandler
from app.ldap_protocol.utils import get_group, get_user, is_user_group_valid
from app.models import NetworkPolicy


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_check_policy(handler: PoolClientHandler) -> None:
    """Check policy."""
    policy = await handler.get_policy(IPv4Address("127.0.0.1"))
    assert policy
    assert policy.netmasks == [IPv4Network("0.0.0.0/0")]


@pytest.mark.asyncio()
async def test_specific_policy_ok(
        handler: PoolClientHandler, session: AsyncSession) -> None:
    """Test specific ip."""
    session.add(NetworkPolicy(
        name='Local policy',
        netmasks=[IPv4Network('127.100.10.5/32')],
        raw=['127.100.10.5/32'],
        enabled=True,
        priority=1,
    ))
    await session.commit()
    policy = await handler.get_policy(IPv4Address("127.100.10.5"))
    assert policy
    assert policy.netmasks == [IPv4Network("127.100.10.5/32")]
    assert not await handler.get_policy(IPv4Address("127.100.10.4"))


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('settings')
async def test_check_policy_group(
        handler: PoolClientHandler, session: AsyncSession) -> None:
    """Check policy."""
    user = await get_user(session, "user0")
    policy = await handler.get_policy(IPv4Address('127.0.0.1'))

    assert policy
    assert await is_user_group_valid(user, policy, session)

    group_dir = await get_group(
        'cn=domain admins,cn=groups,dc=md,dc=test', session)

    policy.groups.append(group_dir.group)
    await session.commit()

    assert await is_user_group_valid(user, policy, session)
