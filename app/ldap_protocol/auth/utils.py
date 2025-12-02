"""Identity utility functions for authentication and user management.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Callable

from sqlalchemy.ext.asyncio import AsyncSession

from entities import User
from ldap_protocol.utils.queries import get_user
from password_utils import PasswordUtils


async def authenticate_user(
    session: AsyncSession,
    username: str,
    password: str,
    password_utils: PasswordUtils,
    update_bad_pwd_count: Callable | None,
) -> User | None:
    """Get user and verify password.

    :param AsyncSession session: sa session
    :param str username: any str
    :param str password: any str
    :return User | None: User model (pydantic).
    """
    user = await get_user(session, username)

    if not user or not user.password:
        return None
    if not password or not password_utils.verify_password(
        password,
        user.password,
    ):
        if update_bad_pwd_count:
            await update_bad_pwd_count(user, is_increase=True)
        return None

    if update_bad_pwd_count:
        await update_bad_pwd_count(user, is_increase=False)
    return user
