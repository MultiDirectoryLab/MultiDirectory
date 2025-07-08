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
from sqlalchemy.orm import InstrumentedAttribute, joinedload, selectinload
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
    """Get base domain directories."""
    result = await session.execute(
        select(Directory)
        .filter(Directory.parent_id.is_(None))
    )  # fmt: skip
    return list(result.scalars().all())


async def get_user(session: AsyncSession, name: str) -> User | None:
    """Get user with username.

    :param AsyncSession session: sqlalchemy session
    :param str name: any name: dn, email or upn
    :return User | None: user from db
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
        .options(joinedload(Directory.group).selectinload(Group.members))
        .options(selectinload(Directory.groups))
    )

    results = await session.scalars(query)

    return list(results.all())


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
        .join(Group.directory, isouter=True)
        .filter(or_(*paths))
        .options(selectinload(Group.members))
        .options(joinedload(Group.directory).selectinload(Directory.groups))
    )

    results = await session.scalars(query)

    return list(results.all())


async def get_group(
    dn: str | GRANT_DN_STRING, session: AsyncSession
) -> Directory:
    """Get dir with group by dn.

    :param str dn: Distinguished Name
    :param AsyncSession session: SA session
    :raises AttributeError: on invalid dn
    :return Directory: dir with group
    """
    for base_directory in await get_base_directories(session):
        if dn_is_base_directory(base_directory, dn):
            raise ValueError("Cannot set memberOf with base dn")

    query = select(Directory).options(joinedload(Directory.group))

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

    :param User | None user: user (sa model)
    :param AsyncSession session: db
    :return bool: exists result
    """
    if user is None:
        return False

    query = (
        select(Group)
        .options(selectinload(Group.users))
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
    """Update lastLogon attr."""
    await session.execute(
        update(User)
        .values({"last_logon": datetime.now(tz=tz)})
        .where(User.id == user.id),
    )
    await session.commit()


def get_search_path(dn: str) -> list[str]:
    """Get search path for dn.

    :param str dn: any DN, dn syntax
    :return list[str]: reversed list of dn values
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

    :param list[str] path: dn
    :param Column field: path column, defaults to Directory.path
    :return ColumnElement: filter (where) element
    """
    return func.array_lowercase(column) == path


def get_filter_from_path(
    dn: str,
    *,
    column: Column | InstrumentedAttribute = Directory.path,
) -> ColumnElement:
    """Get filter condition for path equality from dn."""
    return get_path_filter(get_search_path(dn), column=column)


async def get_dn_by_id(id_: int, session: AsyncSession) -> str:
    """Get dn by id.

    >>> await get_dn_by_id(0, session)
    >>> "cn=groups,dc=example,dc=com"
    """
    query = select(Directory).filter(Directory.id == id_)
    retval = (await session.scalars(query)).one()
    return retval.path_dn


def get_domain_object_class(domain: Directory) -> Iterator[Attribute]:
    """Get default domain attrs."""
    for value in ["domain", "top", "domainDNS"]:
        yield Attribute(name="objectClass", value=value, directory=domain)


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

    :param AsyncSession session: db
    :param int directory_id: id
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

    :param AsyncSession session: db
    :param Directory directory: directory
    :param ZoneInfo tz: timezone info
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

    :param AsyncSession session: db session
    :param str principal_name: the principal name to search for
    :return Directory | None: the principal's directory
    """
    return await session.scalar(
        select(Directory)
        .where(Directory.name == principal_name)
        .options(selectinload(Directory.attributes)),
    )
