"""Test network policy use case with empty groups.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Network

import pytest

from enums import MFAFlags
from ldap_protocol.policies.network import NetworkPolicyUseCase
from ldap_protocol.policies.network.dto import NetworkPolicyDTO, NetworkPolicyUpdateDTO


@pytest.mark.asyncio
async def test_create_policy(network_policy_use_case: NetworkPolicyUseCase) -> None:
    """Test creating policy with empty groups and mfa_groups."""
    dto = NetworkPolicyDTO[None](
        id=None,
        name="Test Empty Groups",
        netmasks=[IPv4Network("192.168.1.0/24")],
        raw=["192.168.1.0/24"],
        priority=2,
        mfa_status=MFAFlags.DISABLED,
        groups=[],
        mfa_groups=[],
    )

    result = await network_policy_use_case.create(dto)
    poicy = await network_policy_use_case.get(result.id)
    assert poicy.groups == []
    assert poicy.mfa_groups == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_update_policy_to_empty_groups(network_policy_use_case: NetworkPolicyUseCase) -> None:
    """Test updating policy from groups to empty."""
    dto = NetworkPolicyDTO[None](
        id=None,
        name="Test Update Groups",
        netmasks=[IPv4Network("172.16.0.0/12")],
        raw=["172.16.0.0/12"],
        priority=3,
        mfa_status=MFAFlags.DISABLED,
        groups=["cn=domain admins,cn=Groups,dc=md,dc=test"],
        mfa_groups=["cn=domain admins,cn=Groups,dc=md,dc=test"],
    )

    created = await network_policy_use_case.create(dto)
    assert created.groups
    assert created.mfa_groups

    update_dto = NetworkPolicyUpdateDTO(id=created.id, groups=[], mfa_groups=[])

    updated = await network_policy_use_case.update(update_dto)

    assert updated.groups == []
    assert updated.mfa_groups == []
