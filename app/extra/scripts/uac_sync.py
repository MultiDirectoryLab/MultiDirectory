"""userAccountControl sync.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from sqlalchemy import Integer, String, cast, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func, select

from ldap_protocol.user_account_control import UserAccountControlFlag
from models.ldap3 import Attribute, User


async def disable_accounts(session: AsyncSession) -> None:
    """Update userAccountControl attr.

    :param AsyncSession session: db

    Original query:
        update "Attributes" a
        set value = (CAST(a.value AS INTEGER) | 2)::text
        from "Users" u
        where (CAST(a.value AS INTEGER) & 2) = 0 and 
            u."accountExpires" < NOW() and 
            a."directoryId" = u."directoryId" and
            a."name" = 'userAccountControl'
    """
    subquery = select(User.directory_id).where(
        User.account_exp < func.now(),
        User.directory_id == Attribute.directory_id).as_scalar()
    new_value = cast(
        cast(Attribute.value, Integer)
        .op('|')(UserAccountControlFlag.ACCOUNTDISABLE),
        String,
    )
    conditions = [
        (
            cast(Attribute.value, Integer)
            .op('&')(UserAccountControlFlag.ACCOUNTDISABLE) == 0
        ),
        Attribute.directory_id.in_(subquery),
        Attribute.name == 'userAccountControl',
    ]
    await session.execute(
        update(Attribute)
        .values(value=new_value)
        .where(*conditions)
        .execution_options(synchronize_session=False))
    await session.commit()
