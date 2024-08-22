"""Access policy manager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.utils import (
    ENTRY_TYPE,
    get_groups,
    get_path_filter,
    get_search_path,
)
from models import AccessPolicy, Directory, Group, Path

__all__ = ['get_policies', 'create_policy']


async def get_policies(session: AsyncSession) -> list[AccessPolicy]:
    """Get policies.

    :param AsyncSession session: db
    :return list[AccessPolicy]: result
    """
    query = (
        select(AccessPolicy)
        .options(
            selectinload(AccessPolicy.groups)
            .selectinload(Group.directory).selectinload(Directory.path),
            selectinload(AccessPolicy.directories)
            .selectinload(Directory.path),
        ))

    return (await session.scalars(query)).all()


async def create_policy(
    name: str,
    can_read: bool,
    can_add: bool,
    can_modify: bool,
    can_delete: bool,
    grant_dn: ENTRY_TYPE,
    groups: list[ENTRY_TYPE],
    session: AsyncSession,
) -> None:
    """Get policies.

    :param ENTRY_TYPE grant_dn: main dn
    :param AsyncSession session: session
    """
    path = get_search_path(grant_dn)
    dir_filter = get_path_filter(
        column=Path.path[1:len(path)],
        path=path)

    directories = await session.scalars(
        select(Directory).join(Directory.path).where(dir_filter))
    groups_dirs = await get_groups(groups, session)

    policy = AccessPolicy(
        name=name,
        can_read=can_read,
        can_add=can_add,
        can_modify=can_modify,
        can_delete=can_delete,
    )
    policy.directories.extend(directories)
    policy.groups.extend(groups_dirs)
    session.add(policy)
    await session.flush()

    await session.refresh(policy)
