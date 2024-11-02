"""userAccountControl sync.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import Integer, String, cast, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func, select

from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.user_account_control import UserAccountControlFlag
from models import Attribute, User


async def disable_accounts(
    session: AsyncSession, kadmin: AbstractKadmin,
) -> None:
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
    subquery = (
        select(User.directory_id)
        .where(
            User.account_exp < func.now(),
            User.directory_id == Attribute.directory_id,
        )
        .scalar_subquery()
    )
    new_value = cast(
        cast(Attribute.value, Integer).op("|")(
            UserAccountControlFlag.ACCOUNTDISABLE,
        ),
        String,
    )
    conditions = [
        (
            cast(Attribute.value, Integer).op("&")(
                UserAccountControlFlag.ACCOUNTDISABLE,
            )
            == 0
        ),
        Attribute.directory_id.in_(subquery),
        Attribute.name == "userAccountControl",
    ]

    ids = await session.scalars(  # noqa: ECE001
        update(Attribute)
        .values(value=new_value)
        .where(*conditions)
        .returning(Attribute.directory_id)
        .execution_options(synchronize_session=False),
    )

    users = await session.stream_scalars(
        select(User).where(User.directory_id.in_(ids)),
    )

    async for user in users:
        await kadmin.lock_principal(user.get_upn_prefix())

    await session.commit()
