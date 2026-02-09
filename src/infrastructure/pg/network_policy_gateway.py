"""Network policies gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import delete, exists, func, select, update, Select, text, true, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from ipaddress import IPv4Address, IPv6Address
from domain.entities import Group, NetworkPolicy, User
from application.policies.network.exceptions import (
    NetworkPolicyAlreadyExistsError,
    NetworkPolicyNotFoundError,
)
from enums import ProtocolType
from application.utils.queries import get_groups
from .tables import queryable_attr as qa


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

    async def get_all(self) -> list[NetworkPolicy]:
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

    def _build_base_query(
        self,
        ip: IPv4Address | IPv6Address,
        protocol_type: ProtocolType,
    ) -> Select:
        """Build a base query for network policies.

        :param IPv4Address | IPv6Address ip: IP address to filter
        :param ProtocolType protocol_type: Protocol to filter
        :param list[int] | None user_group_ids:
            List of user group IDs, optional
        :return: Select query
        """
        protocol_field = getattr(NetworkPolicy, protocol_type)
        query = (
            select(NetworkPolicy)
            .options(
                selectinload(qa(NetworkPolicy.groups)),
                selectinload(qa(NetworkPolicy.mfa_groups)),
            )
            .filter(
                qa(NetworkPolicy.enabled).is_(True),
                text(':ip <<= ANY("Policies".netmasks)').bindparams(ip=ip),
                protocol_field == true(),
            )
            .order_by(qa(NetworkPolicy.priority).asc())
            .limit(1)
        )

        return query

    async def get_by_protocol(
        self,
        ip: IPv4Address | IPv6Address,
        protocol_type: ProtocolType,
    ) -> NetworkPolicy | None:
        """Get network policy by protocol."""
        query = self._build_base_query(ip, protocol_type)
        return await self._session.scalar(query)

    async def get_user_network_policy(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
        policy_type: ProtocolType,
    ) -> NetworkPolicy | None:
        """Get the highest priority network policy for user, ip and protocol.

        :param User user: user object
        :return NetworkPolicy | None: a NetworkPolicy object
        """
        user_group_ids = [group.id for group in user.groups]

        query = self._build_base_query(ip, policy_type)

        if user_group_ids is not None:
            query = query.filter(
                or_(
                    qa(NetworkPolicy.groups) == None,  # noqa
                    qa(NetworkPolicy.groups).any(
                        qa(Group.id).in_(user_group_ids),
                    ),
                ),
            )

        return await self._session.scalar(query)

    async def get_user_http_policy(
        self,
        ip: IPv4Address | IPv6Address,
        user: User,
    ) -> NetworkPolicy | None:
        """Get user HTTP policy."""
        return await self.get_user_network_policy(
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
        return await self.get_user_network_policy(
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
        return await self.get_user_network_policy(
            ip,
            user,
            ProtocolType.LDAP,
        )

    async def check_mfa_group(
        self,
        policy: NetworkPolicy,
        user: User,
    ) -> bool:
        """Check if user is in a group with MFA policy.

        :param NetworkPolicy policy: policy object
        :param User user: user object
        :return bool: status
        """
        return await self._session.scalar(
            select(
                exists().where(  # type: ignore
                    qa(Group.mfa_policies).contains(policy),
                    qa(Group.users).contains(user),
                ),
            ),
        )
    
    async def has_access_to_policy(
        self,
        user: User | None,
        policy: NetworkPolicy | None,
    ) -> bool:
        """Validate user groups, is it including to policy.

        :param User user: db user
        :param NetworkPolicy policy: db policy
        :return bool: status
        """
        query = select(
            select(Group)
            .join(qa(Group.users))
            .join(qa(Group.policies), isouter=True)
            .exists()
            .where(qa(Group.users).contains(user))
            .where(qa(Group.policies).contains(policy)),
        )
        group = await self._session.scalar(query)

        return bool(group)