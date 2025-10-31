"""Network policies use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

from abstract_dao import AbstractService
from ldap_protocol.policies.network.dto import (
    NetworkPolicyDTO,
    NetworkPolicyUpdateDTO,
    SwapPrioritiesDTO,
)
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

    async def update(
        self,
        dto: NetworkPolicyUpdateDTO,
    ) -> NetworkPolicyDTO:
        """Update network policy."""
        groups = mfa_groups = []
        policy = await self._network_policy_gateway.get(dto.id)
        for field in dto.fields_to_update:
            value = getattr(dto, field)
            if value is not None:
                setattr(policy, field, value)

        if dto.netmasks and dto.raw:
            policy.netmasks = dto.netmasks
            policy.raw = dto.raw

        if (
            dto.groups is not None
            and len(dto.groups) > 0
            and len(dto.groups) != 0
        ):
            groups = await self._network_policy_gateway.get_groups(dto.groups)
            policy.groups = [group.directory.path_dn for group in groups]

        if (
            dto.mfa_groups is not None
            and len(dto.mfa_groups) > 0
            and len(dto.mfa_groups) != 0
        ):
            mfa_groups = await self._network_policy_gateway.get_groups(
                dto.mfa_groups,
            )
            policy.mfa_groups = [
                group.directory.path_dn for group in mfa_groups
            ]
        await self._network_policy_gateway.update(
            policy,
            groups,
            mfa_groups,
        )
        return policy

    async def swap_priorities(self, _id1: int, _id2: int) -> SwapPrioritiesDTO:
        """Swap priorities for network policies."""
        return await self._network_policy_gateway.swap_priorities(
            _id1,
            _id2,
        )
