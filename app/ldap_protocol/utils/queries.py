"""Functions for SQL.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from datetime import datetime
from typing import Iterator
from zoneinfo import ZoneInfo

from asyncstdlib.functools import cache
from sqlalchemy import Column, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql.expression import ColumnElement

from models.ldap3 import Attribute, Directory, Group, NetworkPolicy, User

from .const import EMAIL_RE, ENTRY_TYPE
from .helpers import create_object_sid, dn_is_base_directory, validate_entry


@cache
async def get_base_directories(session: AsyncSession) -> list[Directory]:
    """Get base domain directories."""
    result = await session.execute(select(Directory).filter(
        Directory.parent_id.is_(None)))
    return result.scalars().all()


async def get_user(session: AsyncSession, name: str) -> User | None:
    """Get user with username.

    :param AsyncSession session: sqlalchemy session
    :param str name: any name: dn, email or upn
    :return User | None: user from db
    """
    policies = selectinload(User.groups).selectinload(Group.access_policies)

    if '=' not in name:
        if EMAIL_RE.fullmatch(name):
            cond = User.user_principal_name.ilike(name) | User.mail.ilike(name)
        else:
            cond = User.sam_accout_name.ilike(name)

        return await session.scalar(select(User).where(cond).options(policies))

    return await session.scalar(
        select(User)
        .join(User.directory)
        .options(policies)
        .where(get_filter_from_path(name)))


async def get_directories(
        dn_list: list[ENTRY_TYPE], session: AsyncSession) -> list[Directory]:
    """Get directories by dn list."""
    paths = []

    for dn in dn_list:
        for base_directory in await get_base_directories(session):
            if dn_is_base_directory(base_directory, dn):
                continue

            paths.append(get_filter_from_path(dn))

    if not paths:
        return paths

    results = await session.scalars((
        select(Directory)
        .filter(or_(*paths))
        .options(selectinload(Directory.group).selectinload(Group.members))))

    return results.all()


async def get_groups(dn_list: list[str], session: AsyncSession) -> list[Group]:
    """Get dirs with groups by dn list."""
    return [
        directory.group
        for directory in await get_directories(dn_list, session)
        if directory.group is not None]


async def get_group(dn: str | ENTRY_TYPE, session: AsyncSession) -> Directory:
    """Get dir with group by dn.

    :param str dn: Distinguished Name
    :param AsyncSession session: SA session
    :raises AttributeError: on invalid dn
    :return Directory: dir with group
    """
    for base_directory in await get_base_directories(session):
        if dn_is_base_directory(base_directory, dn):
            raise ValueError('Cannot set memberOf with base dn')

    query = (
        select(Directory)
        .options(selectinload(Directory.group)))

    if validate_entry(dn):
        query = query.filter(Directory.path == get_search_path(dn))
    else:
        query = query.filter(Directory.name == dn)

    directory = await session.scalar(query)
    if not directory:
        raise ValueError("Group not found")

    return directory


async def is_user_group_valid(
    user: User,
    policy: NetworkPolicy,
    session: AsyncSession,
) -> bool:
    """Validate user groups, is it including to policy.

    :param User user: db user
    :param NetworkPolicy policy: db policy
    :param AsyncSession session: db
    :return bool: status
    """
    if user is None:
        return False

    if not policy.groups:
        return True

    group = await session.scalar((  # noqa: ECE001
        select(Group)
        .join(Group.users)
        .join(Group.policies, isouter=True)
        .filter(Group.users.contains(user) & Group.policies.contains(policy))
        .limit(1)
    ))
    return bool(group)


async def check_kerberos_group(
        user: User | None, session: AsyncSession) -> bool:
    """Check if user in kerberos group.

    :param User | None user: user (sa model)
    :param AsyncSession session: db
    :return bool: exists result
    """
    if user is None:
        return False

    return await session.scalar(select((  # noqa: ECE001
        select(Group)
        .join(Group.users)
        .join(Group.directory)
        .filter(Group.users.contains(user))
        .filter(Directory.name.ilike("krbadmin"))
        .limit(1)
        .exists()
    )))


async def set_last_logon_user(
        user: User, session: AsyncSession, tz: ZoneInfo) -> None:
    """Update lastLogon attr."""
    await session.execute(
        update(User).values(
            {"last_logon": datetime.now(tz=tz)},
        ).where(
            User.id == user.id,
        ),
    )
    await session.commit()


def get_search_path(dn: str) -> list[str]:
    """Get search path for dn.

    :param str dn: any DN, dn syntax
    :return list[str]: reversed list of dn values
    """
    search_path = [path.strip() for path in dn.lower().split(',')]
    search_path.reverse()
    return search_path


def get_path_filter(
        path: list[str], *, column: Column = Directory.path) -> ColumnElement:
    """Get filter condition for path equality.

    :param list[str] path: dn
    :param Column field: path column, defaults to Directory.path
    :return ColumnElement: filter (where) element
    """
    return func.array_lowercase(column) == path


def get_filter_from_path(
        dn: str, *, column: Column = Directory.path) -> ColumnElement:
    """Get filter condition for path equality from dn."""
    return get_path_filter(get_search_path(dn), column=column)


async def get_dn_by_id(id_: int, session: AsyncSession) -> str:
    """Get dn by id.

    >>> await get_dn_by_id(0, session)
    >>> 'cn=groups,dc=example,dc=com'
    """
    result = await session.scalar(
        select(Directory)
        .filter(Directory.id == id_))

    return result.path_dn


def get_domain_object_class(domain: Directory) -> Iterator[Attribute]:
    """Get default domain attrs."""
    for value in ['domain', 'top', 'domainDNS']:
        yield Attribute(name='objectClass', value=value, directory=domain)


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
        .filter(get_filter_from_path("cn=groups," + base_dn_list[0].path_dn)))

    parent = await session.scalar(query)

    dir_ = Directory(
        object_class='',
        name=name,
        parent=parent,
    )
    dir_.access_policies.extend(parent.access_policies)

    group = Group(directory=dir_)
    dir_.create_path(parent, f"cn={name}")
    session.add_all([dir_, group])
    await session.flush()

    dir_.object_sid = create_object_sid(base_dn_list[0], dir_.id)

    await session.flush()

    attributes: dict[str, list[str]] = {
        "objectClass": ["top", 'posixGroup'],
        'groupType': ['-2147483646'],
        'instanceType': ['4'],
        'sAMAccountName': ['domain users'],
        'sAMAccountType': ['268435456'],
    }

    for name, attr in attributes.items():
        for val in attr:
            session.add(Attribute(name=name, value=val, directory=dir_))

    if sid is not None:
        session.add(
            Attribute(name='objectSid', value=str(sid), directory=dir_))

    await session.flush()
    await session.refresh(dir_)
    await session.refresh(group)
    return dir_, group


async def is_computer(directory_id: int, session: AsyncSession) -> bool:
    """Determine whether the entry is a computer.

    :param AsyncSession session: db
    :param int directory_id: id
    """
    return await session.scalar(select(select(Attribute).where(
        func.lower(Attribute.name) == 'objectclass',
        Attribute.value == 'computer',
        Attribute.directory_id == directory_id).exists()))
