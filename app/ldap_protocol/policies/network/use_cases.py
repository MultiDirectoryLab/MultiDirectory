"""Network policies use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import get_converter, link_function
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_dao import AbstractService
from entities import NetworkPolicy
from enums import ApiPermissionsType
from ldap_protocol.policies.network.dto import (
    NetworkPolicyDTO,
    NetworkPolicyUpdateDTO,
    SwapPrioritiesDTO,
)
from ldap_protocol.policies.network.exceptions import (
    LastActivePolicyError,
    NetworkPolicyAlreadyExistsError,
)

from .gateway import NetworkPolicyGateway


def _convert_groups(policy: NetworkPolicy) -> list[str]:
    """Convert list of Group objects to list of DN strings."""
    return [group.directory.path_dn for group in policy.groups]


def _convert_mfa_groups(policy: NetworkPolicy) -> list[str]:
    """Convert list of Group objects to list of DN strings."""
    return [group.directory.path_dn for group in policy.mfa_groups]


_convert_model_to_dto = get_converter(
    NetworkPolicy,
    NetworkPolicyDTO[int],
    recipe=[
        link_function(
            _convert_groups,
            P[NetworkPolicyDTO].groups,
        ),
        link_function(
            _convert_mfa_groups,
            P[NetworkPolicyDTO].mfa_groups,
        ),
    ],
)

_convert_dto_to_model = get_converter(
    NetworkPolicyDTO[None],
    NetworkPolicy,
)


class NetworkPolicyUseCase(AbstractService):
    """Network policies use cases."""

    _usecase_api_permissions: dict[str, ApiPermissionsType] = {
        "create": ApiPermissionsType.NETWORK_POLICY_CREATE,
        "get_list_policies": ApiPermissionsType.NETWORK_POLICY_GET_LIST_POLICIES,
        "delete": ApiPermissionsType.NETWORK_POLICY_DELETE,
        "switch_network_policy": ApiPermissionsType.NETWORK_POLICY_SWITCH_NETWORK_POLICY,
        "update": ApiPermissionsType.NETWORK_POLICY_UPDATE,
        "swap_priorities": ApiPermissionsType.NETWORK_POLICY_SWAP_PRIORITIES,
    }

    def __init__(
        self,
        network_policy_gateway: NetworkPolicyGateway,
        session: AsyncSession,
    ):
        """Initialize Network policies use cases."""
        self._network_policy_gateway = network_policy_gateway
        self._session = session

    async def create(
        self,
        dto: NetworkPolicyDTO,
    ) -> NetworkPolicyDTO:
        """Create network policy."""
        policy_model = _convert_dto_to_model(dto)
        if dto.groups:
            policy_model.groups = (
                await self._network_policy_gateway.get_groups(dto.groups)
            )
        if dto.mfa_groups:
            policy_model.mfa_groups = (
                await self._network_policy_gateway.get_groups(
                    dto.mfa_groups,
                )
            )

        policy = await self._network_policy_gateway.create(
            policy_model,
        )
        return NetworkPolicyDTO[int](
            id=policy.id,
            name=policy.name,
            netmasks=policy.netmasks,
            priority=policy.priority,
            raw=policy.raw,
            mfa_status=policy.mfa_status,
            is_http=policy.is_http,
            is_ldap=policy.is_ldap,
            is_kerberos=policy.is_kerberos,
            bypass_no_connection=policy.bypass_no_connection,
            bypass_service_failure=policy.bypass_service_failure,
            enabled=policy.enabled,
            groups=dto.groups,
            mfa_groups=dto.mfa_groups,
        )

    async def get(self, _id: int) -> NetworkPolicyDTO[int]:
        policy = await self._network_policy_gateway.get_with_for_update(_id)
        return _convert_model_to_dto(policy)

    async def get_list_policies(
        self,
    ) -> list[NetworkPolicyDTO]:
        """Get list of network policies."""
        policies = await self._network_policy_gateway.get_list_policies()
        return list(map(_convert_model_to_dto, policies))

    async def delete(self, _id: int) -> None:
        """Delete network policy by ID."""
        policy = await self.get(_id)

        await self.validate_policy_count()
        await self._network_policy_gateway.delete(_id)
        await self._network_policy_gateway.update_priority(policy.priority)

    async def switch_network_policy(self, _id: int) -> None:
        """Switch network policy."""
        policy = await self.get(_id)
        if policy.enabled:
            await self.validate_policy_count()
        await self._network_policy_gateway.disable_policy(_id)
        await self._session.commit()

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
        policy = await self._network_policy_gateway.get_with_for_update(dto.id)
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
            policy.groups = await self._network_policy_gateway.get_groups(
                dto.groups,
            )

        if (
            dto.mfa_groups is not None
            and len(dto.mfa_groups) > 0
            and len(dto.mfa_groups) != 0
        ):
            policy.mfa_groups = await self._network_policy_gateway.get_groups(
                dto.mfa_groups,
            )
        if await self._network_policy_gateway.check_policy_exists(policy):
            raise NetworkPolicyAlreadyExistsError(
                "Entry already exists",
            )
        await self._session.commit()
        return _convert_model_to_dto(policy)

    async def swap_priorities(self, id1: int, id2: int) -> SwapPrioritiesDTO:
        """Swap priorities for network policies."""
        policy1 = await self._network_policy_gateway.get(id1)
        policy2 = await self._network_policy_gateway.get(id2)
        policy1.priority, policy2.priority = policy2.priority, policy1.priority
        await self._session.commit()
        return SwapPrioritiesDTO(
            priority1=policy1.priority,
            priority2=policy2.priority,
        )
