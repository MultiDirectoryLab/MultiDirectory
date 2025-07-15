"""Mixin for setting session key cookies in HTTP responses.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import Response
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.utils.queries import set_last_logon_user
from models import User


class ResponseCookieMixin:
    """Provides a method to set a session key as a cookie in a response."""

    async def set_session_cookie(
        self,
        user: User,
        session: AsyncSession,
        settings: Settings,
        response: Response,
        storage: SessionStorage,
        key: str,
    ) -> None:
        """Create a session key and set it as a cookie in the response.

        Update the user's last logon time and set the appropriate cookies
        in the response.

        :param User user: db user
        :param AsyncSession session: db session
        :param Settings settings: app settings
        :param Response response: fastapi response object
        """
        await set_last_logon_user(user, session, settings.TIMEZONE)

        response.set_cookie(
            key="id",
            value=key,
            httponly=True,
            expires=storage.key_ttl,
        )
