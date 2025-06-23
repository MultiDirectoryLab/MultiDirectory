"""Functions for SQL.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import time
from datetime import datetime
from typing import Iterator
from zoneinfo import ZoneInfo

from asyncstdlib.functools import cache
from sqlalchemy import Column, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute, defaultload, selectinload
from sqlalchemy.sql.expression import ColumnElement

from models import Attribute, Directory, Group, User

from .const import EMAIL_RE, GRANT_DN_STRING
from .helpers import (
    create_integer_hash,
    create_object_sid,
    dn_is_base_directory,
    validate_entry,
)


@cache
async def get_base_directories(session: AsyncSession) -> list[Directory]:
    """Get base domain directories.

    Returns:
        list[Directory]: base domain directories
    """
    result = await session.execute(
        select(Directory)
        .filter(Directory.parent_id.is_(None))
    )  # fmt: skip
    return list(result.scalars().all())


async def get_user(session: AsyncSession, name: str) -> User | None:
    """Get user with username.

    Args:
        session (AsyncSession): sqlalchemy session
        name (str): any name: dn, email or upn

    Returns:
        User | None: user from db
    """
    policies = selectinload(User.groups).selectinload(Group.access_policies)

    if "=" not in name:
        if EMAIL_RE.fullmatch(name):
            cond = User.user_principal_name.ilike(name)
        else:
            cond = User.sam_accout_name.ilike(name)

        return await session.scalar(select(User).where(cond).options(policies))

    return await session.scalar(
        select(User)
        .join(User.directory)
        .options(policies)
        .where(get_filter_from_path(name)),
    )


async def get_directories(
    dn_list: list[GRANT_DN_STRING],
    session: AsyncSession,
) -> list[Directory]:
    """Get directories by dn list.

    Args:
        dn_list (list[ENTRY_TYPE]): dn list
        session (AsyncSession): sqlalchemy session

    Returns:
        list[Directory]: directories
    """
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
        .options(defaultload(Directory.group).selectinload(Group.members))
    )

    results = await session.scalars(query)

    return list(results.all())


async def get_groups(dn_list: list[str], session: AsyncSession) -> list[Group]:
    """Get dirs with groups by dn list.

    Args:
        dn_list (list[str]): dn list
        session (AsyncSession): sqlalchemy session

    Returns:
        list[Group]: groups
    """
    return [
        directory.group
        for directory in await get_directories(dn_list, session)
        if directory.group is not None
    ]


async def get_group(
    dn: str | GRANT_DN_STRING, session: AsyncSession
) -> Directory:
    """Get dir with group by dn.

    Args:
        dn (str| ENTRY_TYPE): Distinguished Name
        session (AsyncSession): SA session

    Returns:
        Directory: dir with group

    Raises:
        ValueError: Cannot set memberOf with base dn or group not found
    """
    for base_directory in await get_base_directories(session):
        if dn_is_base_directory(base_directory, dn):
            raise ValueError("Cannot set memberOf with base dn")

    query = select(Directory).options(defaultload(Directory.group))

    if validate_entry(dn):
        query = query.filter(Directory.path == get_search_path(dn))
    else:
        query = query.filter(Directory.name == dn)

    directory = await session.scalar(query)
    if not directory or not directory.group:
        raise ValueError("Group not found")

    return directory


async def check_kerberos_group(
    user: User | None,
    session: AsyncSession,
) -> bool:
    """Check if user in kerberos group.

    Args:
        user (User | None): user (sa model)
        session (AsyncSession): db

    Returns:
        bool: exists result
    """
    if user is None:
        return False

    query = (
        select(Group)
        .join(Group.users)
        .join(Group.directory)
        .filter(Group.users.contains(user))
        .filter(Directory.name.ilike("krbadmin"))
        .limit(1)
        .exists()
    )

    return (await session.scalars(select(query))).one()


async def set_last_logon_user(
    user: User,
    session: AsyncSession,
    tz: ZoneInfo,
) -> None:
    """Update lastLogon attr.

    Args:
        user (User): user
        session (AsyncSession): sqlalchemy session
        tz (ZoneInfo): timezone info
    """
    await session.execute(
        update(User)
        .values({"last_logon": datetime.now(tz=tz)})
        .where(User.id == user.id),
    )
    await session.commit()


def get_search_path(dn: str) -> list[str]:
    """Get search path for dn.

    Returns:
        list[str]: reversed list of dn values
    """
    search_path = [path.strip() for path in dn.lower().split(",")]
    search_path.reverse()
    return search_path


def get_path_filter(
    path: list[str],
    *,
    column: ColumnElement | Column | InstrumentedAttribute = Directory.path,
) -> ColumnElement:
    """Get filter condition for path equality.

    Args:
        path (list[str]): domain name
        column (ColumnElement | Column | InstrumentedAttribute):\
            (Default value = Directory.path)

    Returns:
        ColumnElement: filter (where) element
    """
    return func.array_lowercase(column) == path


def get_filter_from_path(
    dn: str,
    *,
    column: Column | InstrumentedAttribute = Directory.path,
) -> ColumnElement:
    """Get filter condition for path equality from dn.

    Args:
        dn (str): any DN, dn syntax
        column (Column | InstrumentedAttribute): (Default value =\
            Directory.path)

    Returns:
        ColumnElement: filter (where) element
    """
    return get_path_filter(get_search_path(dn), column=column)


async def get_dn_by_id(id_: int, session: AsyncSession) -> str:
    """Get dn by id.

    >>> await get_dn_by_id(0, session)
    >>> "cn=groups,dc=example,dc=com"

    Args:
        id_ (int): id
        session (AsyncSession): Database session

    Returns:
        str: domain name
    """
    query = select(Directory).filter(Directory.id == id_)
    retval = (await session.scalars(query)).one()
    return retval.path_dn


def get_domain_object_class(domain: Directory) -> Iterator[Attribute]:
    """Get default domain attrs.

    Yields:
        Iterator[Attribute]
    """
    for value in ["domain", "top", "domainDNS"]:
        yield Attribute(name="objectClass", value=value, directory=domain)


async def create_group(
    name: str,
    sid: int | None,
    session: AsyncSession,
) -> tuple[Directory, Group]:
    """Create group in default groups path.

    cn=name,cn=groups,dc=domain,dc=com

    Args:
        name (str): group name
        sid (int): objectSid
        session (AsyncSession): db

    Returns:
        tuple[Directory, Group]
    """
    base_dn_list = await get_base_directories(session)

    query = (
        select(Directory)
        .options(selectinload(Directory.access_policies))
        .filter(get_filter_from_path("cn=groups," + base_dn_list[0].path_dn))
    )

    parent = (await session.scalars(query)).one()

    dir_ = Directory(
        object_class="",
        name=name,
        parent=parent,
    )
    dir_.access_policies.extend(parent.access_policies)

    group = Group(directory=dir_)
    dir_.create_path(parent)
    session.add_all([dir_, group])
    await session.flush()

    dir_.object_sid = create_object_sid(
        base_dn_list[0],
        rid=sid or dir_.id,
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
            session.add(Attribute(name=name, value=val, directory=dir_))

    await session.flush()
    await session.refresh(dir_)
    await session.refresh(group)
    return dir_, group


async def is_computer(directory_id: int, session: AsyncSession) -> bool:
    """Determine whether the entry is a computer.

    Args:
        session (AsyncSession): db
        directory_id (int): id

    Returns:
        bool: True if the entry is a computer, False otherwise
    """
    query = select(
        select(Attribute)
        .where(
            Attribute.name.ilike("objectclass"),
            Attribute.value == "computer",
            Attribute.directory_id == directory_id,
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

    Args:
        session (AsyncSession): db
        directory (Directory): directory
        tz (ZoneInfo): timezone info
    """
    now_with_tz = datetime.now(tz=tz)
    absolute_date = int(time.mktime(now_with_tz.timetuple()) / 86400)
    session.add_all([
        Attribute(
            name="nsAccountLock",
            value="true",
            directory=directory,
        ),
        Attribute(
            name="shadowExpire",
            value=str(absolute_date),
            directory=directory,
        ),
    ])


async def get_principal_directory(
    session: AsyncSession,
    principal_name: str,
) -> Directory | None:
    """Fetch the principal's directory by principal name.

    Args:
        session (AsyncSession): db session
        principal_name (str): the principal name to search for

    Returns:
        Directory | None: the principal's directory
    """
    return await session.scalar(
        select(Directory)
        .where(Directory.name == principal_name)
        .options(selectinload(Directory.attributes)),
    )
