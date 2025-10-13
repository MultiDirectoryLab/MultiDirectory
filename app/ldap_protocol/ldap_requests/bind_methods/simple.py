"""Simple auth method.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from entities import User
from ldap_protocol.utils.queries import get_user
from password_manager import PasswordUtils

from .base import AbstractLDAPAuth


class SimpleAuthentication(AbstractLDAPAuth):
    """Simple auth form."""

    METHOD_ID: ClassVar[int] = 0

    @property
    def method_name(self) -> str:
        """Get method name."""
        return "Simple"

    def is_valid(
        self,
        user: User | None,
        password_utils: PasswordUtils,
    ) -> bool:
        """Check if pwd is valid for user.

        :param User | None user: indb user
        :return bool: status
        """
        password = getattr(user, "password", None)
        if password is not None:
            return password_utils.verify_password(
                self.password.get_secret_value(),
                password,
            )
        return False

    def is_anonymous(self) -> bool:
        """Check if auth is anonymous.

        :return bool: status
        """
        return not self.password

    async def get_user(self, session: AsyncSession, username: str) -> User:
        """Get user."""
        return await get_user(session, username)  # type: ignore
