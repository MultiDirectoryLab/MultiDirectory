"""Network policies use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import ClassVar

from adaptix import P
from adaptix.conversion import get_converter, link_function
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_service import AbstractService
from application.policies.network.dto import (
    NetworkPolicyDTO,
    NetworkPolicyUpdateDTO,
    SwapPrioritiesDTO,
)
from application.policies.network.exceptions import (
    LastActivePolicyError,
    NetworkPolicyAlreadyExistsError,
)
from domain.entities import NetworkPolicy, User
from enums import AuthorizationRules, MFAFlags

from .gateway_protocol import NetworkPolicyGatewayProtocol


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

    def __init__(
        self,
        network_policy_gateway: NetworkPolicyGatewayProtocol,
        session: AsyncSession,
    ):
        """Initialize Network policies use cases."""
        self.gateway = network_policy_gateway
        self._session = session

    async def create(
        self,
        dto: NetworkPolicyDTO,
    ) -> None:
        """Create network policy."""
        policy_model = _convert_dto_to_model(dto)
        if dto.groups:
            policy_model.groups = await self.gateway.get_groups(dto.groups)
        if dto.mfa_groups:
            policy_model.mfa_groups = await self.gateway.get_groups(
                dto.mfa_groups,
            )

        await self.gateway.create(policy_model)

    async def get(self, _id: int) -> NetworkPolicyDTO[int]:
        policy = await self.gateway.get_with_for_update(_id)
        return _convert_model_to_dto(policy)

    async def get_list_policies(
        self,
    ) -> list[NetworkPolicyDTO]:
        """Get list of network policies."""
        policies = await self.gateway.get_all()
        return list(map(_convert_model_to_dto, policies))

    async def delete(self, _id: int) -> None:
        """Delete network policy by ID."""
        policy = await self.get(_id)

        await self.validate_policy_count()
        await self.gateway.delete(_id)
        await self.gateway.update_priority(policy.priority)

    async def switch_network_policy(self, _id: int) -> None:
        """Switch network policy."""
        policy = await self.get(_id)
        if policy.enabled:
            await self.validate_policy_count()
        await self.gateway.disable_policy(_id)
        await self._session.commit()

    async def validate_policy_count(self) -> None:
        """Validate policy count."""
        count = await self.gateway.get_policy_count()
        if count == 1:
            raise LastActivePolicyError("At least one policy should be active")

    async def update(
        self,
        dto: NetworkPolicyUpdateDTO,
    ) -> NetworkPolicyDTO:
        """Update network policy."""
        policy = await self.gateway.get_with_for_update(dto.id)

        await self._apply_field_updates(policy, dto)
        await self._apply_netmask_updates(policy, dto)
        await self._apply_group_updates(policy, dto)

        if await self.gateway.check_policy_exists(policy):
            raise NetworkPolicyAlreadyExistsError("Entry already exists")

        await self._session.commit()

        return _convert_model_to_dto(policy)

    async def _apply_field_updates(
        self,
        policy: NetworkPolicy,
        dto: NetworkPolicyUpdateDTO,
    ) -> None:
        """Apply regular field updates."""
        for field in dto.fields_to_update:
            value = getattr(dto, field)
            if value is not None:
                setattr(policy, field, value)

    async def _apply_netmask_updates(
        self,
        policy: NetworkPolicy,
        dto: NetworkPolicyUpdateDTO,
    ) -> None:
        """Apply netmask updates."""
        if dto.netmasks and dto.raw:
            policy.netmasks = dto.netmasks
            policy.raw = dto.raw

    async def _apply_group_updates(
        self,
        policy: NetworkPolicy,
        dto: NetworkPolicyUpdateDTO,
    ) -> None:
        """Apply group updates."""
        if dto.groups is not None:
            policy.groups = (
                await self.gateway.get_groups(dto.groups) if dto.groups else []
            )

        if dto.mfa_groups is not None:
            policy.mfa_groups = (
                await self.gateway.get_groups(dto.mfa_groups)
                if dto.mfa_groups
                else []
            )

    async def swap_priorities(self, id1: int, id2: int) -> SwapPrioritiesDTO:
        """Swap priorities for network policies."""
        policy1 = await self.gateway.get(id1)
        policy2 = await self.gateway.get(id2)
        policy1.priority, policy2.priority = policy2.priority, policy1.priority
        await self._session.commit()
        return SwapPrioritiesDTO(
            priority1=policy1.priority,
            priority2=policy2.priority,
        )

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        create.__name__: AuthorizationRules.NETWORK_POLICY_CREATE,
        get_list_policies.__name__: AuthorizationRules.NETWORK_POLICY_GET_LIST_POLICIES,  # noqa: E501
        delete.__name__: AuthorizationRules.NETWORK_POLICY_DELETE,
        switch_network_policy.__name__: AuthorizationRules.NETWORK_POLICY_SWITCH_NETWORK_POLICY,  # noqa: E501
        update.__name__: AuthorizationRules.NETWORK_POLICY_UPDATE,
        swap_priorities.__name__: AuthorizationRules.NETWORK_POLICY_SWAP_PRIORITIES,  # noqa: E501
    }


class NetworkPolicyValidatorUseCase(AbstractService):
    """Network policies validator use cases."""

    _gateway: NetworkPolicyGatewayProtocol

    def __init__(
        self,
        network_policy_gateway: NetworkPolicyGatewayProtocol,
    ):
        """Initialize Network policies validator use cases."""
        self._gateway = network_policy_gateway

    async def get_user_http_policy(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user HTTP policy."""
        return await self._gateway.get_http_policy_by_user(
            ip,
            user,
        )

    async def get_user_kerberos_policy(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user Kerberos policy."""
        return await self._gateway.get_kerberos_policy_by_user(
            ip,
            user,
        )

    async def check_mfa_group(
        self,
        policy: NetworkPolicy,
        user: User,
    ) -> bool:
        """Check if user is in a group with MFA policy."""
        return await self._gateway.check_mfa_group(
            policy,
            user,
        )

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        get_user_http_policy.__name__: AuthorizationRules.NETWORK_POLICY_VALIDATOR_GET_USER_HTTP_POLICY,  # noqa: E501
        get_user_kerberos_policy.__name__: AuthorizationRules.NETWORK_POLICY_VALIDATOR_GET_USER_KERBEROS_POLICY,  # noqa: E501
        check_mfa_group.__name__: AuthorizationRules.NETWORK_POLICY_VALIDATOR_CHECK_MFA_GROUP,  # noqa: E501
    }


class ValidatePolicyAccessUseCase:
    """Validates user access according to network policy rules.

    This use case implements the business logic for determining whether a user
    is allowed to access resources based on the configured network policy.

    Business Rules:
    1. If no policy is attached to the session,
        access is DENIED (secure by default)
    2. If policy has no group restrictions, access is GRANTED
    3. Otherwise, check if user belongs to any of the policy's allowed groups

    Note: This implements a whitelist approach - only explicitly allowed
    groups have access when policy has group restrictions.
    """

    _gateway: NetworkPolicyGatewayProtocol

    def __init__(
        self,
        network_policy_gateway: NetworkPolicyGatewayProtocol,
    ):
        """Initialize Validate user with network policy use case."""
        self._gateway = network_policy_gateway

    async def execute(
        self,
        policy: NetworkPolicy,
        user: User,
    ) -> bool:
        """Execute use case."""
        if not policy.groups:
            return True

        return await self._gateway.has_access_to_policy(
            policy,
            user,
        )


class ValidateMFARequirementUseCase:
    """Validates if MFA is required according to network policy rules."""

    _gateway: NetworkPolicyGatewayProtocol

    def __init__(
        self,
        network_policy_gateway: NetworkPolicyGatewayProtocol,
    ) -> None:
        """Initialize Validate MFA requirement use case."""
        self._gateway = network_policy_gateway

    async def execute(
        self,
        policy: NetworkPolicy,
        user: User,
    ) -> bool:
        """Execute use case."""
        if policy.mfa_status == MFAFlags.DISABLED:
            return False

        if policy.mfa_status == MFAFlags.WHITELIST:
            return await self._gateway.check_mfa_group(
                policy,
                user,
            )

        return True
