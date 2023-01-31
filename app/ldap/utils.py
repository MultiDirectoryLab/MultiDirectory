"""Utils module for different functions."""
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
