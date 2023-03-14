"""Utils module for different functions."""
from datetime import datetime

import pytz
from asyncio_cache import cache as async_cache
from sqlalchemy import select

from models.database import async_session
from models.ldap3 import CatalogueSetting


@async_cache
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
