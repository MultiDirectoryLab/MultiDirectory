"""Network policies gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix.conversion import get_converter
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Group, NetworkPolicy
from ldap_protocol.policies.network.dto import NetworkPolicyDTO
from ldap_protocol.policies.network.exceptions import (
    NetworkPolicyAlreadyExistsError,
)
from ldap_protocol.utils.queries import get_groups

_converter = get_converter(NetworkPolicyDTO, NetworkPolicy)


class NetworkPolicyGateway:
    """Network policy gateway."""

    def __init__(self, session: AsyncSession):
        """Initialize Network policy gateway."""
        self._session = session

    async def create(
        self,
        dto: NetworkPolicyDTO,
        groups: list[Group],
        mfa_groups: list[Group],
    ) -> NetworkPolicy:
        """Get network policy."""
        policy = NetworkPolicy(
            name=dto.name,
            netmasks=dto.netmasks,
            priority=dto.priority,
            raw=dto.raw,
            mfa_status=dto.mfa_status,
            is_http=dto.is_http,
            is_ldap=dto.is_ldap,
            is_kerberos=dto.is_kerberos,
            bypass_no_connection=dto.bypass_no_connection,
            bypass_service_failure=dto.bypass_service_failure,
        )

        if dto.groups:
            policy.groups = groups
        if dto.mfa_groups:
            policy.mfa_groups = mfa_groups

        try:
            self._session.add(policy)
            await self._session.commit()
            await self._session.refresh(policy)
            return policy
        except IntegrityError:
            raise NetworkPolicyAlreadyExistsError(
                "Entry already exists",
            )

    async def get_groups(
        self,
        groups: list[str],
    ) -> list[Group]:
        return await get_groups(groups, self._session)
