"""User Adapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import Response, status

from api.base_adapter import BaseAdapter
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.identity.current_user_manager import CurrentUserManager
from ldap_protocol.identity.exceptions.auth import (
    LoginFailedError,
    UnauthorizedError,
)


class CurrentUserGateway(BaseAdapter[CurrentUserManager]):
    """Gateway for user operations."""

    _exceptions_map = {
        LoginFailedError: status.HTTP_403_FORBIDDEN,
        UnauthorizedError: status.HTTP_401_UNAUTHORIZED,
    }

    async def get_current_user(self) -> UserSchema:
        """Load the authenticated user using request-bound session data."""
        return await self._service.get_current_user()

    async def rekey_session(self, response: Response) -> None:
        """Rotate session key if needed and refresh the response cookie."""
        try:
            key = await self._service.rekey_session()
            if key:
                response.set_cookie(
                    key="id",
                    value=key,
                    httponly=True,
                    expires=self._service.key_ttl,
                )
        except KeyError as err:
            raise UnauthorizedError("Login failed") from err
