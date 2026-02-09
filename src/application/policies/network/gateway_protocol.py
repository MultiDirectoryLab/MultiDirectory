"""Network policy validator protocol.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from domain.entities import NetworkPolicy, User, Group
from enums import ProtocolType

from abstract_db_gateway import AbstractDBGateWay


class NetworkPolicyGatewayProtocol(AbstractDBGateWay[NetworkPolicy, int]):
    """Protocol for validating network policies."""

    async def get_all(self) -> list[NetworkPolicy]:
        ...

    async def get_with_for_update(self, _id: int) -> NetworkPolicy:
        ...

    async def get_groups(self, groups: list[str]) -> list[Group]:
        ...

    async def get_policy_count(self) -> int:
        ...

    async def update_priority(self, priority: int) -> None:
        ...

    async def disable_policy(self, _id: int) -> None:
        ...

    async def check_policy_exists(self, policy: NetworkPolicy) -> bool:
        ...

    async def get_by_protocol(
        self,
        ip: IPv4Address | IPv6Address,
        protocol_type: ProtocolType,
    ) -> NetworkPolicy | None:
        """Get network policy by protocol."""
        ...

    async def _get_policy_by_user(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
        protocol_type: ProtocolType,
    ) -> NetworkPolicy | None:
        """Get user policy."""
        ...

    async def get_http_policy_by_user(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user HTTP policy."""
        return await self._get_policy_by_user(ip, user, ProtocolType.HTTP)

    async def get_kerberos_policy_by_user(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user Kerberos policy."""
        return await self._get_policy_by_user(ip, user, ProtocolType.KERBEROS)

    async def get_ldap_policy_by_user(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user LDAP policy."""
        return await self._get_policy_by_user(ip, user, ProtocolType.LDAP)

    async def check_mfa_group(  # халивар
        self,
        policy: NetworkPolicy,
        user: User,
    ) -> bool:
        """Check if user is in a group with MFA policy."""
        ...

    async def has_access_to_policy(
        self,
        policy: NetworkPolicy,
        user: User,
    ) -> bool:
        """Check if user is in a valid group for the policy."""
        ...