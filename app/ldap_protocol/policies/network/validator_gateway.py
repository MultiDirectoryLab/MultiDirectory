"""Network policy validator gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from sqlalchemy import exists, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql.expression import Select, true

from entities import Group, NetworkPolicy, User
from enums import ProtocolType
from repo.pg.tables import queryable_attr as qa


class NetworkPolicyValidatorGateway:
    """Gateway for validating network policies."""

    def __init__(
        self,
        session: AsyncSession,
    ):
        """Initialize validator gateway."""
        self._session = session

    def _build_base_query(
        self,
        ip: IPv4Address | IPv6Address,
        protocol_type: ProtocolType,
    ) -> Select:
        """Build a base query for network policies.

        :param IPv4Address | IPv6Address ip: IP address to filter
        :param ProtocolType protocol_type: Protocol type
            protocol: Protocol to filter
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

    async def is_user_group_valid(
        self,
        user: User | None,
        policy: NetworkPolicy | None,
    ) -> bool:
        """Validate user groups, is it including to policy.

        :param User user: db user
        :param NetworkPolicy policy: db policy
        :return bool: status
        """
        if not (user and policy):
            return False

        if not policy.groups:
            return True
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
