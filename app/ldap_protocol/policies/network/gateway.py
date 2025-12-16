"""Network policies gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import delete, exists, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from entities import Group, NetworkPolicy
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

    async def get(self, _id: int) -> NetworkPolicy:
        """Get network policy."""
        policy = await self._session.scalar(
            select(NetworkPolicy)
            .filter_by(id=_id)
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
        return policy

    async def create(
        self,
        policy: NetworkPolicy,
    ) -> NetworkPolicy:
        """Get network policy."""
        try:
            self._session.add(policy)
            await self._session.flush()
            await self._session.refresh(policy)
            return policy
        except IntegrityError:
            raise NetworkPolicyAlreadyExistsError("Entry already exists")

    async def get_groups(self, groups: list[str]) -> list[Group]:
        return await get_groups(groups, self._session)

    async def get_list_policies(self) -> list[NetworkPolicy]:
        result = await self._session.scalars(
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
        return list(result)

    async def get_with_for_update(self, _id: int) -> NetworkPolicy:
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
        return policy

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

    async def update_priority(self, priority: int) -> None:
        await self._session.execute(
            update(NetworkPolicy)
            .values({"priority": NetworkPolicy.priority - 1})
            .filter(qa(NetworkPolicy.priority) > priority),
        )

    async def disable_policy(self, _id: int) -> None:
        await self._session.execute(
            update(NetworkPolicy).filter_by(id=_id).values(enabled=False),
        )

    async def check_policy_exists(self, policy: NetworkPolicy) -> bool:
        result = await self._session.scalars(
            select(
                exists(NetworkPolicy).where(
                    qa(NetworkPolicy.name) == policy.name,
                    qa(NetworkPolicy.netmasks) == policy.netmasks,
                    qa(NetworkPolicy.id) != policy.id,
                ),
            ),
        )
        return result.one()
