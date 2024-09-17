"""userAccountControl sync.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from sqlalchemy import Integer, String, cast, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func, select

from models.ldap3 import Attribute, User


async def update_uac_accounts(session: AsyncSession) -> None:
    """Update userAccountControl attr.

    :param AsyncSession session: db
    """
    subquery = select(User.directory_id).where(
        User.account_exp < func.now(),
        User.directory_id == Attribute.directory_id).as_scalar()
    await session.execute(  # noqa
        update(Attribute)
        .values(value=cast(cast(Attribute.value, Integer).op('|')(2), String))
        .where(
            cast(Attribute.value, Integer).op('&')(2) == 0,
            Attribute.directory_id.in_(subquery),
            Attribute.name == 'userAccountControl')
        .execution_options(synchronize_session=False))
    await session.commit()
