"""userAccountControl sync.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import Integer, String, cast, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import func, select

from config import Settings
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.queries import add_lock_and_expire_attributes
from models import Attribute, User, attributes_table, users_table


async def disable_accounts(
    session: AsyncSession,
    kadmin: AbstractKadmin,
    settings: Settings,
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
        select(users_table.c.directory_id)
        .where(
            users_table.c.account_exp < func.now(),
            users_table.c.directory_id == attributes_table.c.directory_id,
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
        attributes_table.c.directory_id.in_(subquery),
        attributes_table.c.name == "userAccountControl",
    ]

    ids = await session.scalars(
        update(Attribute)
        .values(value=new_value)
        .where(*conditions)
        .returning(attributes_table.c.directory_id)
        .execution_options(synchronize_session=False),
    )

    users = await session.stream_scalars(
        select(User)
        .where(users_table.c.directory_id.in_(ids)),
    )  # fmt: skip

    async for user in users:
        await kadmin.lock_principal(user.get_upn_prefix())

        await add_lock_and_expire_attributes(
            session,
            user.directory,
            settings.TIMEZONE,
        )

    await session.commit()
