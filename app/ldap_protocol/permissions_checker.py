"""Api permissions checker."""

from functools import wraps
from typing import Awaitable, Callable, ParamSpec, TypeVar

from ldap_protocol.identity.identity_provider import IdentityProvider

_P = ParamSpec("_P")
_R = TypeVar("_R")


class ApiPermissionError(Exception):
    """API permission error."""


class ApiPermissionsChecker:
    """API permissions checker."""

    def __init__(self, identity_provider: IdentityProvider) -> None:
        """Initialize."""
        self._identity_provider = identity_provider

    async def has_permission(self, permission: str) -> bool:
        """Check if current user has permission.

        :param str permission: permission to check
        :return: bool
        """
        user = await self._identity_provider.get_current_user()
        if not user:
            return False

        return permission in user.api_permissions

    async def check_permission(self, permission: str) -> None:
        """Check if current user has permission, raise error if not.

        :param str permission: permission to check
        :raises ApiPermissionError: if user does not have permission
        :return: None
        """
        if not await self.has_permission(permission):
            raise ApiPermissionError(
                f"User does not have permission: {permission}",
            )

    def wrap_use_case(
        self,
        permission_name: str,
        func: Callable[_P, Awaitable[_R]],
    ) -> Callable[_P, Awaitable[_R]]:
        @wraps(func)
        async def wrapped_use_case(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            """Wrap callback_mfa to handle session management."""
            await self.check_permission(permission_name)
            return await func(*args, **kwargs)

        return wrapped_use_case  # type: ignore
