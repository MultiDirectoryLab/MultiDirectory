"""Identity utility functions for authentication and user management.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from entities import User
from ldap_protocol.utils.queries import get_user
from password_manager import PasswordValidator


async def authenticate_user(
    session: AsyncSession,
    username: str,
    password: str,
    password_validator: PasswordValidator,
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
    if not password_validator.verify_password(password, user.password):
        return None
    return user
