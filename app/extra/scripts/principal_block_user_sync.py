"""Principal and user account block sync.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime

from sqlalchemy import Integer, String, cast, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import select

from config import Settings
from ldap_protocol.user_account_control import (
    UserAccountControlFlag,
    get_check_uac,
)
from ldap_protocol.utils.queries import (
    add_lock_and_expire_attributes,
    get_principal_directory,
)
from models import Attribute, Directory, User


async def principal_block_sync(
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Synchronize principal and user account blocking."""
    for user in await session.scalars(select(User)):
        uac_check = await get_check_uac(session, user.directory_id)
        if uac_check(UserAccountControlFlag.ACCOUNTDISABLE):
            continue

        if "@" in user.user_principal_name:
            principal_postfix = user.user_principal_name.split("@")[1].upper()
            principal_name = f"{user.get_upn_prefix()}@{principal_postfix}"
        else:
            continue

        principal_directory = await get_principal_directory(
            session=session,
            principal_name=principal_name,
        )
        if not principal_directory:
            continue

        krb_exp_attr = _find_krb_exp_attr(principal_directory)
        if (not krb_exp_attr) or (not krb_exp_attr.value):
            continue

        expiration_time = datetime.strptime(
            krb_exp_attr.value,
            "%Y%m%d%H%M%SZ",
        ).replace(
            tzinfo=settings.TIMEZONE,
        )

        now = datetime.now(tz=settings.TIMEZONE)
        if expiration_time > now:
            continue

        new_value = cast(
            cast(Attribute.value, Integer).op("|")(
                UserAccountControlFlag.ACCOUNTDISABLE,
            ),
            String,
        )

        conditions = [
            Attribute.directory_id == user.directory_id,
            Attribute.name == "userAccountControl",
        ]

        await session.execute(
            update(Attribute)
            .values(value=new_value)
            .where(*conditions)
            .execution_options(synchronize_session=False),
        )

        await add_lock_and_expire_attributes(
            session=session,
            directory=user.directory,
            tz=settings.TIMEZONE,
        )

        await session.commit()


def _find_krb_exp_attr(directory: Directory) -> Attribute | None:
    """Find krbprincipalexpiration attribute in directory.

    Args:
        directory (Directory): the directory object

    Returns:
        Atrribute | None: the attribute with the name
        'krbprincipalexpiration', or None if not found.
    """
    for attr in directory.attributes:
        if attr.name == "krbprincipalexpiration":
            return attr
    return None
