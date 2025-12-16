"""Test policy api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv4Network

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from entities import NetworkPolicy
from enums import ProtocolType
from ldap_protocol.policies.network import (
    NetworkPolicyGateway,
    NetworkPolicyValidatorProtocol,
)
from ldap_protocol.utils.queries import get_group, get_user


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_check_policy(
    network_policy_gateway: NetworkPolicyGateway,
) -> None:
    """Check policy."""
    policy = await network_policy_gateway.get_by_protocol(
        IPv4Address("127.0.0.1"),
        ProtocolType.LDAP,
    )
    assert policy
    assert policy.netmasks == [IPv4Network("0.0.0.0/0")]


@pytest.mark.asyncio
async def test_specific_policy_ok(
    network_policy_gateway: NetworkPolicyGateway,
    session: AsyncSession,
) -> None:
    """Test specific ip."""
    session.add(
        NetworkPolicy(
            name="Local policy",
            netmasks=[IPv4Network("127.100.10.5/32")],
            raw=["127.100.10.5/32"],
            enabled=True,
            priority=1,
        ),
    )
    await session.commit()
    policy = await network_policy_gateway.get_by_protocol(
        ip=IPv4Address("127.100.10.5"),
        protocol_type=ProtocolType.LDAP,
    )
    assert policy
    assert policy.netmasks == [IPv4Network("127.100.10.5/32")]
    assert not await network_policy_gateway.get_by_protocol(
        ip=IPv4Address("127.100.10.4"),
        protocol_type=ProtocolType.LDAP,
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("settings")
async def test_check_policy_group(
    network_policy_validator: NetworkPolicyValidatorProtocol,
    network_policy_gateway: NetworkPolicyGateway,
    session: AsyncSession,
) -> None:
    """Check policy."""
    user = await get_user(session, "user0")
    assert user

    policy = await network_policy_gateway.get_by_protocol(
        IPv4Address("127.0.0.1"),
        ProtocolType.LDAP,
    )
    assert policy

    assert await network_policy_validator.is_user_group_valid(user, policy)

    group = await get_group(
        dn="cn=domain admins,cn=groups,dc=md,dc=test",
        session=session,
    )

    policy.groups.append(group)
    await session.commit()

    assert await network_policy_validator.is_user_group_valid(user, policy)
