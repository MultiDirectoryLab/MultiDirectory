"""Network policies gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from entities import Group, NetworkPolicy
from ldap_protocol.policies.network.dto import NetworkPolicyDTO
from ldap_protocol.policies.network.exceptions import (
    NetworkPolicyAlreadyExistsError,
)
from ldap_protocol.utils.queries import get_groups
from repo.pg.tables import queryable_attr as qa


class NetworkPolicyGateway:
    """Network policy gateway."""

    def __init__(self, session: AsyncSession):
        """Initialize Network policy gateway."""
        self._session = session

    # async def get()
    async def create(
        self,
        dto: NetworkPolicyDTO,
        groups: list[Group],
        mfa_groups: list[Group],
    ) -> NetworkPolicyDTO:
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
            return NetworkPolicyDTO(
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
        except IntegrityError:
            raise NetworkPolicyAlreadyExistsError(
                "Entry already exists",
            )

    async def get_groups(
        self,
        groups: list[str],
    ) -> list[Group]:
        return await get_groups(groups, self._session)

    async def get_list_policies(
        self,
    ) -> list[NetworkPolicyDTO]:
        policies = await self._session.scalars(
            select(NetworkPolicy)
            .options(
                selectinload(qa(NetworkPolicy.groups)).selectinload(
                    qa(Group.directory),
                ),
                selectinload(qa(NetworkPolicy.mfa_groups)).selectinload(
                    qa(Group.directory),
                ),
            )
            .order_by(qa(NetworkPolicy.priority).asc()),
        )
        return [
            NetworkPolicyDTO(
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
                groups=[group.directory.path_dn for group in policy.groups],
                mfa_groups=[
                    group.directory.path_dn for group in policy.mfa_groups
                ],
            )
            for policy in policies
        ]
