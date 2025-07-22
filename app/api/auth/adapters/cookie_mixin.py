"""Mixin for setting session key cookies in HTTP responses.

Provides a method to set a session key as a cookie in a FastAPI response,
and updates the user's last logon time.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import Response


class ResponseCookieMixin:
    """Provides a method to set a session key as a cookie in a response."""

    async def set_session_cookie(
        self,
        response: Response,
        key_ttl: int,
        key: str,
    ) -> None:
        """Create a session key and set it as a cookie in the response.

        Update the user's last logon time and set the appropriate cookies
        in the response.

        :param Response response: fastapi response object
        :param int key_ttl: session key time-to-live
        :param str key: session key
        """
        response.set_cookie(
            key="id",
            value=key,
            httponly=True,
            expires=key_ttl,
        )
