"""Utils module for different functions."""
from datetime import datetime

import pytz
from asyncio_cache import cache
from sqlalchemy import select

from models.database import async_session
from models.ldap3 import CatalogueSetting


@cache
async def get_base_dn() -> str:
    """Get base dn for e.g. DC=multifactor,DC=dev.

    :return str: name for the base distinguished name.
    """
    async with async_session() as session:
        cat_result = await session.execute(
            select(CatalogueSetting)
            .filter(CatalogueSetting.name == 'defaultNamingContext'),
        )
        return ','.join((
            f'DC={value}' for value in
            cat_result.scalar_one().value.split('.')))


@cache
async def get_domain() -> str:
    """Get domain name in normal form (multifactor.dev)."""
    async with async_session() as session:
        cat_result = await session.execute(
            select(CatalogueSetting)
            .filter(CatalogueSetting.name == 'defaultNamingContext'),
        )
        return cat_result.scalar_one().value


def get_generalized_now():
    """Get generalized time (formated) with tz."""
    return datetime.now(  # NOTE: possible setting
        pytz.timezone('Europe/Moscow')).strftime('%Y%m%d%H%M%S.%f%z')
