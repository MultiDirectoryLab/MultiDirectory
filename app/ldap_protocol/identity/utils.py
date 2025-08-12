"""Identity utility functions for authentication and user management.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.utils.queries import get_user
from models import User
from password_manager import verify_password


async def authenticate_user(
    session: AsyncSession,
    username: str,
    password: str,
) -> User | None:
    """Get user and verify password.

    :param AsyncSession session: sa session
    :param str username: any str
    :param str password: any str
    :return User | None: User model (pydantic).
    """
    user = await get_user(session, username)

    if not user or not user.password or not password:
        return None
    if not verify_password(password, user.password):
        return None
    return user
