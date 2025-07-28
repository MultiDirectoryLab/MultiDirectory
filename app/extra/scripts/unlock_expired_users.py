"""Unlock expired users by removing LDAP lock attributes.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.policies.lockout_policy import AuthLockoutService


async def unlock_expired_users(
    session: AsyncSession, settings: Settings
) -> None:
    """Remove LDAP lock attributes from users whose lockout has expired."""
    lockout_service = AuthLockoutService(settings)
    await lockout_service.unlock_expired_bulk(session)
