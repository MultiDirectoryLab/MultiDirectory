"""Utils module for different functions."""
import re
from datetime import datetime

import pytz
from asyncstdlib.functools import cache
from sqlalchemy import select

from models.database import AsyncSession, async_session
from models.ldap3 import CatalogueSetting, Path, User

email_re = re.compile(
    r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")


@cache
async def get_base_dn(normal: bool = False) -> str:
    """Get base dn for e.g. DC=multifactor,DC=dev.

    :return str: name for the base distinguished name.
    """
    async with async_session() as session:
        cat_result = await session.execute(
            select(CatalogueSetting)
            .filter(CatalogueSetting.name == 'defaultNamingContext'),
        )
        if normal:
            return cat_result.scalar_one().value

        return ','.join((
            f'dc={value}' for value in
            cat_result.scalar_one().value.split('.')))


def get_attribute_types() -> list[str]:
    """Get attribute types from file.

    :return list[list[str]]: attrs
    """
    with open('extra/adTypes.txt', 'r') as file:
        return [line.replace(')\n', ' )') for line in file]


def get_object_classes() -> list[str]:
    """Get attribute types from file.

    :return list[list[str]]: attrs
    """
    with open('extra/adClasses.txt', 'r') as file:
        return list(file)


def get_generalized_now():
    """Get generalized time (formated) with tz."""
    return datetime.now(  # NOTE: possible setting
        pytz.timezone('Europe/Moscow')).strftime('%Y%m%d%H%M%S.%f%z')


def _get_path(name):
    """Get path from name."""
    return [
        item.lower() for item in reversed(name.split(','))
        if not item[:2] in ('DC', 'dc')
    ]


def _get_domain(name):
    """Get domain from name."""
    return '.'.join([
        item[3:].lower() for item in name.split(',')
        if item[:2] in ('DC', 'dc')
    ])


async def get_user(session: AsyncSession, name: str) -> User | None:
    """Get user with username.

    :param AsyncSession session: sqlalchemy session
    :param str name: any name: dn, email or upn
    :return User | None: user from db
    """
    if '=' not in name:
        if email_re.fullmatch(name):
            cond = User.user_principal_name == name or User.mail == name
        else:
            cond = User.sam_accout_name == name

        return await session.scalar(select(User).where(cond))

    path = await session.scalar(
        select(Path).where(Path.path == _get_path(name)))

    domain = await session.scalar(
        select(CatalogueSetting)
        .where(
            CatalogueSetting.name == 'defaultNamingContext',
            CatalogueSetting.value == _get_domain(name),
        ))

    if not domain or not path:
        return None

    return await session.scalar(
        select(User).where(User.directory == path.endpoint))
