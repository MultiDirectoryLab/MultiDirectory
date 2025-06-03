"""CTE funcs.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import or_
from sqlalchemy.ext.asyncio import AsyncScalarResult, AsyncSession
from sqlalchemy.sql.expression import select
from sqlalchemy.sql.selectable import CTE

from models import Directory, DirectoryMembership, Group

from .queries import get_filter_from_path


def find_members_recursive_cte(dn: str) -> CTE:
    """Create CTE to filter group memberships based on directory hierarchy.

    This function generates a recursive CTE that starts with an initial
    directory hierarchy and then recursively includes directory memberships,
    effectively capturing all groups associated with the specified directory
    name (DN) and their members.

    Function Workflow:
    ------------------

    1. **Base Query (Initial Part of the CTE)**:
       The function begins by defining the initial part of the CTE, named
       `directory_hierarchy`. This query selects the `directory_id` and
       `group_id` from the `Directory` and `Groups` tables, filtering based
       on the distinguished name (DN) provided by the `dn` argument.

    2. **Recursive Part of the CTE**:
       The second part of the CTE is recursive. It joins the results of
       `directory_hierarchy` with the `DirectoryMemberships` table to find
       all groups that are members of other groups, iterating through
       all nested memberships.

    3. **Combining Results**:
       The CTE combines the initial and recursive parts using `union_all`
       effectively creating a recursive query that gathers all directorie
       and their associated groups, both directly and indirectly related.

    4. **Final Query**:
       The final query applies the method (typically a comparison operation
       to the results of the CTE, returning the desired condition for furthe
       use in the main query.

    The query translates to the following SQL:

    WITH RECURSIVE anon_1(directory_id, group_id) as (
        SELECT "Directory".id as directory_id, "Groups".id as group_id
        FROM "Directory"
        JOIN "Groups" ON "Directory".id = "Groups"."directoryId"
        WHERE "Directory"."path" =
                '{dc=test,dc=md,cn=groups,"cn=domain admins"}'

        UNION ALL

        SELECT "DirectoryMemberships".directory_id  AS directory_id,
               "Groups".id AS group_id
        FROM "DirectoryMemberships"
        JOIN anon_1 ON anon_1.group_id = "DirectoryMemberships".group_id
        LEFT OUTER JOIN "Groups" ON "DirectoryMemberships".directory_id =
                                   "Groups"."directoryId"
    )
    SELECT * FROM anon_1;

    Example:
    -------
    Group1 includes user1, user2, and group2.
    Group2 includes users user3 and group3.
    Group3 includes user4.

    In the case of a recursive search through the specified group1, the search
    result will be as follows: user1, user2, group2, user3, group3, user4.

    """
    directory_hierarchy = (
        select(Directory.id.label("directory_id"), Group.id.label("group_id"))
        .join(Directory.group)
        .select_from(Directory)
        .where(get_filter_from_path(dn))
    ).cte(recursive=True)
    recursive_part = (
        select(
            DirectoryMembership.directory_id.label("directory_id"),
            Group.id.label("group_id"),
        )
        .select_from(DirectoryMembership)
        .join(
            directory_hierarchy,
            directory_hierarchy.c.group_id == DirectoryMembership.group_id,
        )
        .join(
            Group,
            DirectoryMembership.directory_id == Group.directory_id,
            isouter=True,
        )
    )
    return directory_hierarchy.union_all(recursive_part)


def find_root_group_recursive_cte(dn_list: list) -> CTE:
    """Create CTE to filter directory root group.

    The query translates to the following SQL:

    WITH RECURSIVE anon_1(directory_id, group_id) as (
        SELECT "Directory".id as directory_id, "Groups".id as group_id
        FROM "Directory"
        LEFT OUTER JOIN "Groups" ON "Directory".id = "Groups"."directoryId"
        WHERE "Directory"."path" =
                '{dc=test,dc=md,cn=groups,"cn=domain admins"}'

        UNION ALL

        SELECT "DirectoryMemberships".directory_id  AS directory_id,
               "Groups".id AS group_id
        FROM "DirectoryMemberships"
        JOIN anon_1 ON anon_1.directory_id =
                       "DirectoryMemberships".directory_id
        JOIN "Groups" ON "DirectoryMemberships".group_id = "Groups"."group_id"
    )
    SELECT * FROM anon_1;

    Example:
    -------
    Group1 includes user1, user2, and group2.
    Group2 includes users user3 and group3.
    Group3 includes user4.

    In the case of a recursive search through the specified user4, the search
    result will be as follows: group1, group2, group3,
    user4.

    """
    directory_hierarchy = (
        select(
            Directory.id.label("directory_id"),
            Group.id.label("group_id"),
        )
        .select_from(Directory)
        .join(Directory.group, isouter=True)
        .where(or_(*[get_filter_from_path(dn) for dn in dn_list]))
    ).cte(recursive=True)
    recursive_part = (
        select(
            Group.directory_id.label("directory_id"),
            Group.id.label("group_id"),
        )
        .select_from(DirectoryMembership)
        .join(
            directory_hierarchy,
            directory_hierarchy.c.directory_id
            == DirectoryMembership.directory_id,
        )
        .join(Group, DirectoryMembership.group_id == Group.id)
    )
    return directory_hierarchy.union_all(recursive_part)


async def get_members_root_group(
    dn: str,
    session: AsyncSession,
) -> list[Directory]:
    """Get all members root group by dn.

    Example:
    -------
    Group1 includes user1, user2, and group2.
    Group2 includes users user3 and group3.
    Group3 includes user4.

    In the case of a recursive search through the specified user4, the search
    result will be as follows: group1, user1, user2, group2, user3, group3,
    user4.

    """
    cte = find_root_group_recursive_cte([dn])
    result = await session.scalars(select(cte.c.directory_id))
    group_ids = result.all()

    if not group_ids:
        return []

    root_group_id = group_ids[-1]

    directory = await session.scalar(
        select(Directory)
        .where(Directory.id == root_group_id)
    )  # fmt: skip

    if not directory:
        raise RuntimeError

    cte = find_members_recursive_cte(directory.path_dn)
    result = await session.scalars(select(cte.c.directory_id))
    dir_ids = result.all()

    if not dir_ids:
        return []

    query = (
        select(Directory)
        .where(
            or_(
                *[Directory.id == dir_id for dir_id in dir_ids],
            )
        )
    )  # fmt: skip

    retval = await session.scalars(query)

    return list(retval.all())


async def get_all_parent_group_directories(
    groups: list[Group],
    session: AsyncSession,
) -> AsyncScalarResult | None:
    """Get all parent groups directory.

    Args:
        groups (list[Group]): directory groups
        session (AsyncSession): session

    Returns:
        set[Directory]: all groups and their parent group directories
    """
    dn_list = [group.directory.path_dn for group in groups]

    if not dn_list:
        return None

    cte = find_root_group_recursive_cte(dn_list)
    result = await session.scalars(select(cte.c.directory_id).distinct())
    directories_ids = result.all()

    if not directories_ids:
        return None

    query = select(Directory).where(Directory.id.in_(directories_ids))

    return await session.stream_scalars(query)
