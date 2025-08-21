"""Cookie mixins for setting and retrieving session and MFA cookies.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

from fastapi import Request, Response

CookieKey = Literal["id", "mfa"]


class ResponseCookieMixin:
    """Methods to set session-related cookies on a FastAPI response."""

    def _set_cookie(
        self,
        response: Response,
        key: CookieKey,
        value: str,
        ttl: int,
    ) -> None:
        """Set a cookie on the response.

        Args:
            response (Response): FastAPI response object.
            key (CookieKey): Cookie name (``"id"`` or ``"mfa"``).
            value (str): Cookie value.
            ttl (int): Time-to-live in seconds (passed to ``expires``).

        Returns:
            None

        """
        response.set_cookie(
            key=key,
            value=value,
            httponly=True,
            expires=ttl,
        )

    def set_session_cookie(
        self,
        response: Response,
        value: str,
        ttl: int,
    ) -> None:
        """Set the primary session cookie (``id``).

        Args:
            response (Response): FastAPI response object.
            value (str): Session key value.
            ttl (int): Time-to-live in seconds.

        Returns:
            None

        """
        self._set_cookie(response, "id", value, ttl)

    def set_mfa_session_cookie(
        self,
        response: Response,
        value: str,
        ttl: int,
    ) -> None:
        """Set the MFA session cookie (``mfa``).

        Args:
            response (Response): FastAPI response object.
            value (str): MFA session key value.
            ttl (int): Time-to-live in seconds.

        Returns:
            None

        """
        self._set_cookie(response, "mfa", value, ttl)


class RequestCookieMixin:
    """Methods to read session and MFA cookies from a FastAPI request."""

    def _get_cookie(self, request: Request, key: CookieKey) -> str:
        """Return a cookie value or empty string if absent.

        Args:
            request (Request): FastAPI request object.
            key (CookieKey): Cookie name (``"id"`` or ``"mfa"``).

        Returns:
            str: Cookie value or ``""`` if not set.

        """
        return request.cookies.get(key, "")

    def get_session_cookie(self, request: Request) -> str:
        """Get the primary session cookie value.

        Args:
            request (Request): FastAPI request object.

        Returns:
            str: Session cookie value or empty string.

        """
        return self._get_cookie(request, "id")

    def get_mfa_session_cookie(self, request: Request) -> str:
        """Get the MFA session cookie value.

        Args:
            request (Request): FastAPI request object.

        Returns:
            str: MFA cookie value or empty string.

        """
        return self._get_cookie(request, "mfa")
