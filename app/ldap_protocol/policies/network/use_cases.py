"""Network policies use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abstract_dao import AbstractService
from entities import Group, NetworkPolicy
from ldap_protocol.policies.network.dto import NetworkPolicyDTO

from .gate_way import NetworkPolicyGateway


class NetworkPolicyUseCase(AbstractService):
    """Network policies use cases."""

    def __init__(self, network_policy_gateway: NetworkPolicyGateway):
        """Initialize Network policies use cases."""
        self._network_policy_gateway = network_policy_gateway

    async def create(
        self,
        dto: NetworkPolicyDTO,
    ) -> tuple[NetworkPolicy, list[Group], list[Group]]:
        """Create network policy."""
        groups = mfa_groups = []
        if dto.groups:
            groups = await self._network_policy_gateway.get_groups(dto.groups)
        if dto.mfa_groups:
            mfa_groups = await self._network_policy_gateway.get_groups(
                dto.mfa_groups,
            )

        policy = await self._network_policy_gateway.create(
            dto,
            groups,
            mfa_groups,
        )
        return policy, groups, mfa_groups
