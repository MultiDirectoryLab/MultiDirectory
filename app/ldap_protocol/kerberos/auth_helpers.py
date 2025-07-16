"""Helper functions for Kerberos user authentication.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.utils.queries import get_user
from models import User
from security import verify_password


async def authenticate_user(
    session: AsyncSession,
    username: str,
    password: str,
) -> User | None:
    """Retrieve a user from the database and verify the password.

    :param session: SQLAlchemy AsyncSession
    :param username: Username (DN, UPN, sAMAccountName, etc.)
    :param password: User password
    :return: User if found and password matches, otherwise None
    """
    user = await get_user(session, username)

    if not user or not user.password or not password:
        return None

    if not verify_password(password, user.password):
        return None

    return user
