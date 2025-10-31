"""Network policies gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from entities import Group, NetworkPolicy
from ldap_protocol.policies.network.dto import NetworkPolicyDTO
from ldap_protocol.policies.network.exceptions import (
    NetworkPolicyAlreadyExistsError,
    NetworkPolicyNotFoundError,
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

    async def get(self, _id: int) -> NetworkPolicyDTO:
        policy = await self._session.scalar(
            select(NetworkPolicy)
            .filter_by(id=_id)
            .with_for_update()
            .options(
                selectinload(qa(NetworkPolicy.groups)).selectinload(
                    qa(Group.directory),
                ),
                selectinload(qa(NetworkPolicy.mfa_groups)).selectinload(
                    qa(Group.directory),
                ),
            ),
        )
        if not policy:
            raise NetworkPolicyNotFoundError(
                f"Policy with id {_id} not found.",
            )
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
            groups=[group.directory.path_dn for group in policy.groups],
            mfa_groups=[
                group.directory.path_dn for group in policy.mfa_groups
            ],
        )

    async def delete(self, _id: int) -> None:
        await self._session.execute(
            delete(NetworkPolicy)
            .filter_by(id=_id),
        )  # fmt: skip
        await self._session.flush()

    async def get_policy_count(self) -> int:
        count = await self._session.scalars(
            select(func.count())
            .select_from(NetworkPolicy)
            .filter_by(enabled=True),
        )
        return count.one()

    async def delete_with_update_priority(
        self,
        _id: int,
        priority: int,
    ) -> None:
        async with self._session.begin_nested():
            await self.delete(_id)
            await self._session.execute(
                update(NetworkPolicy)
                .values({"priority": NetworkPolicy.priority - 1})
                .filter(qa(NetworkPolicy.priority) > priority),
            )

    async def disable_policy(
        self,
        _id: int,
    ) -> None:
        await self._session.execute(
            update(NetworkPolicy).filter_by(id=_id).values({"enabled": False}),
        )
        await self._session.commit()
