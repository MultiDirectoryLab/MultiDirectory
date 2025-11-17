"""userAccountControl attribute handling.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Attribute
from ldap_protocol.objects import (
    UserAccountControlFlag as UserAccountControlFlag,
)
from ldap_protocol.utils.queries import get_user


async def get_check_uac(
    session: AsyncSession,
    directory_id: int,
) -> Callable[[UserAccountControlFlag], bool]:
    """Get userAccountControl attribute and check binary flags in it.

    :param AsyncSession session: SA async session
    :param int directory_id: id
    :return Callable: function to check given flag in current
        userAccountControl attribute
    """
    query = (
        select(Attribute)
        .filter_by(directory_id=directory_id, name="userAccountControl")
    )  # fmt: skip
    uac = await session.scalar(query)

    value: str = (
        uac.value if uac is not None and uac.value is not None else "0"
    )

    def is_flag_true(flag: UserAccountControlFlag) -> bool:
        """Check given flag in current userAccountControl attribute.

        :param userAccountControlFlag flag: flag
        :return bool: result
        """
        return bool(int(value) & flag)

    return is_flag_true


async def check_service_account_active(
    session: AsyncSession,
    upn: str | None,
    uac: int | None,
) -> bool:
    """Check external aac for internal match."""
    if not upn:
        return False

    user = await get_user(session, upn)
    if user is None:
        return False

    uac_check = await get_check_uac(session, user.directory_id)

    if uac_check(UserAccountControlFlag.ACCOUNTDISABLE):
        return False

    acc_flag = (
        uac_check(UserAccountControlFlag.TEMP_DUPLICATE_ACCOUNT)
        or uac_check(UserAccountControlFlag.NORMAL_ACCOUNT)
        or uac_check(UserAccountControlFlag.INTERDOMAIN_TRUST_ACCOUNT)
        or uac_check(UserAccountControlFlag.WORKSTATION_TRUST_ACCOUNT)
        or uac_check(UserAccountControlFlag.SERVER_TRUST_ACCOUNT)
    )
    uac = uac if uac is not None else 0

    return not (uac and acc_flag)
