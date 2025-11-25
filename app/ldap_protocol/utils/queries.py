"""Functions for SQL.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import time
from datetime import datetime
from typing import Iterator
from zoneinfo import ZoneInfo

from sqlalchemy import Column, exists, func, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute, joinedload, selectinload
from sqlalchemy.sql.expression import ColumnElement

from entities import Attribute, Directory, Group, User
from repo.pg.tables import (
    directory_memberships_table,
    directory_table,
    queryable_attr as qa,
)

from .const import EMAIL_RE, GRANT_DN_STRING
from .helpers import (
    create_integer_hash,
    create_object_sid,
    dn_is_base_directory,
    ft_now,
    validate_entry,
)


async def get_base_directories(session: AsyncSession) -> list[Directory]:
    """Get base domain directories."""
    result = await session.execute(
        select(Directory)
        .filter(qa(Directory.parent_id).is_(None)),
    )  # fmt: skip
    return list(result.scalars().all())


async def get_user(session: AsyncSession, name: str) -> User | None:
    """Get user with username.

    :param AsyncSession session: sqlalchemy session
    :param str name: any name: dn, email or upn
    :return User | None: user from db
    """
    policies = selectinload(qa(User.groups)).selectinload(qa(Group.roles))

    if "=" not in name:
        if EMAIL_RE.fullmatch(name):
            cond = qa(User.user_principal_name).ilike(name)
        else:
            cond = qa(User.sam_account_name).ilike(name)

        return await session.scalar(
            select(User).where(cond).options(policies),
        )

    return await session.scalar(
        select(User)
        .join(qa(User.directory))
        .options(policies)
        .where(get_filter_from_path(name)),
    )


async def get_directories(
    dn_list: list[GRANT_DN_STRING],
    session: AsyncSession,
    excluded_group: Group | None = None,
) -> list[Directory]:
    """Get directories by dn list."""
    paths = []

    for dn in dn_list:
        for base_directory in await get_base_directories(session):
            if dn_is_base_directory(base_directory, dn):
                continue

            paths.append(get_filter_from_path(dn))

    if not paths:
        return paths  # type: ignore

    query = (
        select(Directory)
        .filter(or_(*paths))
        .options(joinedload(qa(Directory.group)))
    )

    if excluded_group:
        excluded_subq = select(
            directory_memberships_table.c.directory_id,
        ).where(
            directory_memberships_table.c.group_id == excluded_group.id,
        )
        query = query.where(
            ~exists(
                excluded_subq.where(
                    directory_memberships_table.c.directory_id == Directory.id,
                ),
            ),
        )

    results = await session.scalars(query)

    return list(results.all())


async def extend_group_membership(
    group: Group,
    members_to_add: list[Directory],
    session: AsyncSession,
) -> None:
    """Extend group memberships."""
    await session.execute(
        insert(directory_memberships_table).values(
            [
                {"group_id": group.id, "directory_id": directory.id}
                for directory in members_to_add
            ],
        ),
    )


async def clear_group_membership(
    group: Group,
    session: AsyncSession,
) -> None:
    """Clear group memberships."""
    await session.execute(
        directory_memberships_table.delete().where(
            directory_memberships_table.c.group_id == group.id,
        ),
    )


async def sync_group_membership(
    group: Group,
    allowed_members: list[Directory],
    session: AsyncSession,
) -> None:
    """Remove group memberships not in allowed list."""
    new_ids = {member.id for member in allowed_members}
    await session.execute(
        directory_memberships_table.delete().where(
            directory_memberships_table.c.group_id == group.id,
            directory_memberships_table.c.directory_id.not_in(new_ids),
        ),
    )


async def remove_from_group_membership(
    group: Group,
    members_to_remove: list[Directory],
    session: AsyncSession,
) -> None:
    """Remove directories from group memberships."""
    member_ids = {member.id for member in members_to_remove}
    await session.execute(
        directory_memberships_table.delete().where(
            directory_memberships_table.c.group_id == group.id,
            directory_memberships_table.c.directory_id.in_(member_ids),
        ),
    )


async def get_directory_by_rid(
    rid: str,
    session: AsyncSession,
) -> Directory | None:
    """Get directory by relative ID (rid).

    :param str rid: relative ID
    :param AsyncSession session: SA session
    :return Directory | None: directory or None
    """
    query = (
        select(Directory)
        .options(joinedload(qa(Directory.group)))
        .filter(qa(Directory.object_sid).endswith(f"-{rid}"))
    )
    return await session.scalar(query)


async def get_groups(dn_list: list[str], session: AsyncSession) -> list[Group]:
    """Get dirs with groups by dn list."""
    paths = []

    for dn in dn_list:
        for base_directory in await get_base_directories(session):
            if dn_is_base_directory(base_directory, dn):
                continue

            paths.append(get_filter_from_path(dn))

    if not paths:
        return paths  # type: ignore

    query = (
        select(Group)
        .join(qa(Group.directory), isouter=True)
        .filter(or_(*paths))
        .options(selectinload(qa(Group.members)))
        .options(
            joinedload(qa(Group.directory)).selectinload(qa(Directory.groups)),
        )
    )

    results = await session.scalars(query)

    return list(results.all())


async def get_group(
    dn: str | GRANT_DN_STRING,
    session: AsyncSession,
) -> Group:
    """Get dir with group by dn.

    :param str dn: Distinguished Name
    :param AsyncSession session: SA session
    :raises AttributeError: on invalid dn
    :return Directory: dir with group
    """
    query = (
        select(Group)
        .join(qa(Group.directory), isouter=True)
        .options(joinedload(qa(Group.directory)))
    )

    if validate_entry(dn):
        query = query.filter_by(path=get_search_path(dn))
    else:
        query = query.filter_by(name=dn)

    group = await session.scalar(query)
    if not group:
        raise ValueError("Group not found")

    return group


async def set_user_logon_attrs(
    user: User,
    session: AsyncSession,
    tz: ZoneInfo,
) -> None:
    """Update attrs that need to be changed with user logon.

    pwdLastSet, last_logon
    """
    await session.execute(
        update(Attribute)
        .values({"value": ft_now()})
        .filter_by(
            directory_id=user.directory_id,
            name="pwdLastSet",
            value="-1",
        ),
    )
    await session.execute(
        update(User)
        .values({"last_logon": datetime.now(tz=tz)})
        .filter_by(id=user.id),
    )
    await session.commit()


def get_search_path(dn: str) -> list[str]:
    """Get search path for dn.

    :param str dn: any DN, dn syntax
    :return list[str]: reversed list of dn values
    """
    if not dn:
        return []

    search_path = []
    for path in dn.lower().split(","):
        key, value = path.split("=")
        search_path.append(f"{key.strip()}={value.strip()}")
    search_path.reverse()
    return search_path


def get_path_filter(
    path: list[str],
    *,
    column: ColumnElement
    | Column
    | InstrumentedAttribute = directory_table.c.path,
) -> ColumnElement:
    """Get filter condition for path equality.

    :param list[str] path: dn
    :param Column field: path column, defaults to Directory.path
    :return ColumnElement: filter (where) element
    """
    return func.array_lowercase(column) == path


def get_filter_from_path(
    dn: str,
    *,
    column: Column | InstrumentedAttribute = directory_table.c.path,
) -> ColumnElement:
    """Get filter condition for path equality from dn."""
    return get_path_filter(get_search_path(dn), column=column)


async def get_dn_by_id(id_: int, session: AsyncSession) -> str:
    """Get dn by id.

    >>> await get_dn_by_id(0, session)
    >>> "cn=groups,dc=example,dc=com"
    """
    query = select(Directory).filter_by(id=id_)
    retval = (await session.scalars(query)).one()
    return retval.path_dn


def get_domain_object_class(domain: Directory) -> Iterator[Attribute]:
    """Get default domain attrs."""
    for value in ["domain", "top", "domainDNS"]:
        yield Attribute(
            name="objectClass",
            value=value,
            directory_id=domain.id,
        )


async def create_group(
    name: str,
    sid: int | None,
    session: AsyncSession,
) -> tuple[Directory, Group]:
    """Create group in default groups path.

    cn=name,cn=groups,dc=domain,dc=com

    :param str name: group name
    :param int sid: objectSid
    :param AsyncSession session: db
    """
    base_dn_list = await get_base_directories(session)

    query = select(Directory).filter(
        get_filter_from_path("cn=groups," + base_dn_list[0].path_dn),
    )

    parent = (await session.scalars(query)).one()

    dir_ = Directory(
        object_class="",
        name=name,
        parent=parent,
    )
    session.add(dir_)
    await session.flush()
    await session.refresh(dir_, ["id"])

    group = Group(directory_id=dir_.id)
    dir_.create_path(parent)
    session.add(group)

    dir_.object_sid = create_object_sid(
        base_dn_list[0],
        rid=sid or dir_.id,
        reserved=bool(sid),
    )

    await session.flush()

    attributes: dict[str, list[str]] = {
        "objectClass": ["top", "posixGroup", "group"],
        "groupType": ["-2147483646"],
        "instanceType": ["4"],
        "sAMAccountName": [dir_.name],
        dir_.rdname: [dir_.name],
        "sAMAccountType": ["268435456"],
        "gidNumber": [str(create_integer_hash(dir_.name))],
    }

    for name, attr in attributes.items():
        for val in attr:
            session.add(Attribute(name=name, value=val, directory_id=dir_.id))

    await session.flush()
    await session.refresh(dir_)
    await session.refresh(group)
    return dir_, group


async def is_computer(directory_id: int, session: AsyncSession) -> bool:
    """Determine whether the entry is a computer.

    :param AsyncSession session: db
    :param int directory_id: id
    """
    query = select(
        select(Attribute)
        .where(
            qa(Attribute.name).ilike("objectclass"),
            qa(Attribute.value) == "computer",
            qa(Attribute.directory_id) == directory_id,
        )
        .exists(),
    )
    return (await session.scalars(query)).one()


async def add_lock_and_expire_attributes(
    session: AsyncSession,
    directory: Directory,
    tz: ZoneInfo,
) -> None:
    """Add `nsAccountLock` and `shadowExpire` attributes to the directory.

    :param AsyncSession session: db
    :param Directory directory: directory
    :param ZoneInfo tz: timezone info
    """
    now_with_tz = datetime.now(tz=tz)
    absolute_date = int(time.mktime(now_with_tz.timetuple()) / 86400)
    session.add_all(
        [
            Attribute(
                name="nsAccountLock",
                value="true",
                directory_id=directory.id,
            ),
            Attribute(
                name="shadowExpire",
                value=str(absolute_date),
                directory_id=directory.id,
            ),
        ],
    )


async def get_principal_directory(
    session: AsyncSession,
    principal_name: str,
) -> Directory | None:
    """Fetch the principal's directory by principal name.

    :param AsyncSession session: db session
    :param str principal_name: the principal name to search for
    :return Directory | None: the principal's directory
    """
    return await session.scalar(
        select(Directory)
        .filter_by(name=principal_name)
        .options(selectinload(qa(Directory.attributes))),
    )


async def set_or_update_primary_group(
    directory_dn: GRANT_DN_STRING,
    group_dn: GRANT_DN_STRING,
    session: AsyncSession,
) -> None:
    """Set or update primary group for a directory.

    :param str directory_dn: directory DN
    :param str group_dn: group DN
    :param AsyncSession session: database session
    :raises ValueError: if directory or group not found
    """
    directory = await session.scalar(
        select(Directory)
        .filter(get_filter_from_path(directory_dn)),
    )  # fmt: skip

    if not directory:
        raise ValueError(f"Directory with DN '{directory_dn}' not found.")

    group = await get_group(group_dn, session)

    existing_attr = await session.scalar(
        select(Attribute)
        .filter_by(
            name="primaryGroupID",
            directory_id=directory.id,
        ),
    )  # fmt: skip

    if existing_attr:
        existing_attr.value = group.directory.relative_id
    else:
        session.add(
            Attribute(
                name="primaryGroupID",
                value=group.directory.relative_id,
                directory_id=directory.id,
            ),
        )

    await session.commit()
