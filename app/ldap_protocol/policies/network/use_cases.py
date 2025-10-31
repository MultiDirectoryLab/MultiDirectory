"""Network policies use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

from abstract_dao import AbstractService
from ldap_protocol.policies.network.dto import NetworkPolicyDTO
from ldap_protocol.policies.network.exceptions import LastActivePolicyError

from .gate_way import NetworkPolicyGateway


class NetworkPolicyUseCase(AbstractService):
    """Network policies use cases."""

    def __init__(self, network_policy_gateway: NetworkPolicyGateway):
        """Initialize Network policies use cases."""
        self._network_policy_gateway = network_policy_gateway

    async def create(
        self,
        dto: NetworkPolicyDTO,
    ) -> NetworkPolicyDTO:
        """Create network policy."""
        groups = mfa_groups = []
        if dto.groups:
            groups = await self._network_policy_gateway.get_groups(dto.groups)
        if dto.mfa_groups:
            mfa_groups = await self._network_policy_gateway.get_groups(
                dto.mfa_groups,
            )

        policy_dto = await self._network_policy_gateway.create(
            dto,
            groups,
            mfa_groups,
        )
        return policy_dto

    async def get_list_policies(
        self,
    ) -> list[NetworkPolicyDTO]:
        """Get list of network policies."""
        return await self._network_policy_gateway.get_list_policies()

    async def delete(self, _id: int) -> None:
        """Delete network policy by ID."""
        policy = await self._network_policy_gateway.get(_id)

        await self.validate_policy_count()

        await self._network_policy_gateway.delete_with_update_priority(
            _id,
            policy.priority,
        )

    async def switch_network_policy(self, _id: int) -> Literal[True]:
        """Switch network policy."""
        policy = await self._network_policy_gateway.get(_id)
        if policy.enabled:
            await self.validate_policy_count()
        await self._network_policy_gateway.disable_policy(_id)
        return True

    async def validate_policy_count(self) -> None:
        """Validate policy count."""
        count = await self._network_policy_gateway.get_policy_count()
        if count == 1:
            raise LastActivePolicyError("At least one policy should be active")
