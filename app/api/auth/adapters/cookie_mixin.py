"""Mixin for setting session key cookies in HTTP responses.

Provides a method to set a session key as a cookie in a FastAPI response,
and updates the user's last logon time.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import Response

from ldap_protocol.session_storage import SessionStorage


class ResponseCookieMixin:
    """Provides a method to set a session key as a cookie in a response."""

    async def set_session_cookie(
        self,
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
        response.set_cookie(
            key="id",
            value=key,
            httponly=True,
            expires=storage.key_ttl,
        )
