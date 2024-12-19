"""Multifactor status monitoring.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.multifactor import (
    MFAStatus,
    MultifactorAPI,
    get_mfa_check_interval,
    update_mfa_status,
)

TASK_INTERVAL = 50.0


async def ping_multifactor(
    session: AsyncSession,
    mfa: MultifactorAPI,
) -> None:
    """Ping multifactor and update status.

    :param AsyncSession session: db
    :param MultifactorAPI mfa: multifactor api
    """
    interval = await get_mfa_check_interval(session)

    if not mfa:
        await asyncio.sleep(interval - TASK_INTERVAL)
        return

    if not await mfa.ping():
        await update_mfa_status(session, MFAStatus.UNAVAILABLE)

    await asyncio.sleep(interval - TASK_INTERVAL)
