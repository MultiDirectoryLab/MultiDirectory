"""Network policy validator gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from entities import NetworkPolicy, User
from enums import ProtocolType
from ldap_protocol.policies.network.gateway import NetworkPolicyGateway


class NetworkPolicyValidatorGateway:
    """Gateway for validating network policies."""

    def __init__(self, network_policy_gateway: NetworkPolicyGateway):
        """Initialize validator gateway."""
        self._network_policy_gateway = network_policy_gateway

    async def get_user_http_policy(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user HTTP policy."""
        return await self._network_policy_gateway.get_user_network_policy(
            ip,
            user,
            ProtocolType.HTTP,
        )

    async def get_user_kerberos_policy(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user Kerberos policy."""
        return await self._network_policy_gateway.get_user_network_policy(
            ip,
            user,
            ProtocolType.KERBEROS,
        )

    async def get_user_ldap_policy(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user LDAP policy."""
        return await self._network_policy_gateway.get_user_network_policy(
            ip,
            user,
            ProtocolType.LDAP,
        )

    async def check_mfa_group(
        self,
        policy: NetworkPolicy,
        user: User,
    ) -> bool:
        """Check if user is in a group with MFA policy."""
        return await self._network_policy_gateway.check_mfa_group(
            policy,
            user,
        )

    async def is_user_group_valid(
        self,
        user: User | None,
        policy: NetworkPolicy | None,
    ) -> bool:
        """Validate user groups, is it including to policy."""
        return await self._network_policy_gateway.is_user_group_valid(
            user,
            policy,
        )
