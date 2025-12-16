"""Network policy validator protocol.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import Protocol

from entities import NetworkPolicy, User


class NetworkPolicyValidatorProtocol(Protocol):
    """Protocol for validating network policies."""

    async def get_user_http_policy(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user HTTP policy."""
        ...

    async def get_user_kerberos_policy(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user Kerberos policy."""
        ...

    async def get_user_ldap_policy(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user LDAP policy."""
        ...

    async def check_mfa_group(
        self,
        policy: NetworkPolicy,
        user: User,
    ) -> bool:
        """Check if user is in a group with MFA policy."""
        ...

    async def is_user_group_valid(
        self,
        user: User | None,
        policy: NetworkPolicy | None,
    ) -> bool:
        """Validate user groups, is it including to policy."""
        ...
