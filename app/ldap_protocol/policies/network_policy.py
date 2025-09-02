"""Network policy manager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from sqlalchemy import exists, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql.expression import Select, true

from models import (
    Group,
    NetworkPolicy,
    User,
    groups_table,
    policies_table,
    queryable_attr as qa,
)


def build_policy_query(
    ip: IPv4Address | IPv6Address,
    protocol_field_name: Literal["is_http", "is_ldap", "is_kerberos"],
    user_group_ids: list[int] | None = None,
) -> Select:
    """Build a base query for network policies with optional group filtering.

    :param IPv4Address ip: IP address to filter
    :param Literal["is_http", "is_ldap", "is_kerberos"] protocol_field_name
        protocol: Protocol to filter
    :param list[int] | None user_group_ids: List of user group IDs, optional
    :return: Select query
    """
    protocol_field = getattr(NetworkPolicy, protocol_field_name)
    query = (
        select(NetworkPolicy)
        .filter_by(enabled=True)
        .options(
            selectinload(qa(NetworkPolicy.groups)),
            selectinload(qa(NetworkPolicy.mfa_groups)),
        )
        .filter(
            text(':ip <<= ANY("Policies".netmasks)').bindparams(ip=ip),
            protocol_field == true(),
        )
        .order_by(policies_table.c.priority.asc())
        .limit(1)
    )

    if user_group_ids is not None:
        return query.filter(
            or_(
                qa(NetworkPolicy.groups) == None,  # noqa
                qa(NetworkPolicy.groups).any(
                    groups_table.c.id.in_(user_group_ids),
                ),
            ),
        )

    return query


async def check_mfa_group(
    policy: NetworkPolicy,
    user: User,
    session: AsyncSession,
) -> bool:
    """Check if user is in a group with MFA policy.

    :param NetworkPolicy policy: policy object
    :param User user: user object
    :param AsyncSession session: db session
    :return bool: status
    """
    return await session.scalar(
        select(
            exists().where(  # type: ignore
                qa(Group.mfa_policies).contains(policy),
                qa(Group.users).contains(user),
            ),
        ),
    )


async def get_user_network_policy(
    ip: IPv4Address | IPv6Address,
    user: User,
    session: AsyncSession,
) -> NetworkPolicy | None:
    """Get the highest priority network policy for user, ip and protocol.

    :param User user: user object
    :param AsyncSession session: db session
    :return NetworkPolicy | None: a NetworkPolicy object
    """
    user_group_ids = [group.id for group in user.groups]

    query = build_policy_query(ip, "is_http", user_group_ids)

    return await session.scalar(query)


async def is_user_group_valid(
    user: User | None,
    policy: NetworkPolicy | None,
    session: AsyncSession,
) -> bool:
    """Validate user groups, is it including to policy.

    :param User user: db user
    :param NetworkPolicy policy: db policy
    :param AsyncSession session: db
    :return bool: status
    """
    if user is None or policy is None:
        return False

    if not policy.groups:
        return True

    query = (
        select(Group)
        .join(qa(Group.users))
        .join(qa(Group.policies), isouter=True)
        .where(qa(Group.users).contains(user))
        .where(qa(Group.policies).contains(policy))
        .limit(1)
    )

    group = await session.scalar(query)
    return bool(group)
