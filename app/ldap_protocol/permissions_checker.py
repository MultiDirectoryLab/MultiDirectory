"""Api permissions checker."""

from functools import wraps
from typing import Awaitable, Callable, ParamSpec, TypeVar

from enums import ApiPermissionsType
from ldap_protocol.identity import IdentityProvider

_P = ParamSpec("_P")
_R = TypeVar("_R")


class ApiPermissionError(Exception):
    """API permission error."""


class ApiPermissionsChecker:
    """API permissions checker."""

    def __init__(self, identity_provider: IdentityProvider) -> None:
        """Set current user.

        :param UserSchema | None user: current user
        :return: None
        """
        self._idp = identity_provider

    async def _has_permission(self, permission: ApiPermissionsType) -> bool:
        """Check if current user has permission.

        :param ApiPermissionsType permission: permission to check
        :return: bool
        """
        user = await self._idp.get_current_user()
        return permission in user.api_permissions

    async def check_permission(self, permission: ApiPermissionsType) -> None:
        """Check if current user has permission, raise error if not.

        :param ApiPermissionsType permission: permission to check
        :raises ApiPermissionError: if user does not have permission
        :return: None
        """
        if not await self._has_permission(permission):
            raise ApiPermissionError(
                f"User does not have permission: {permission}",
            )

    def wrap_use_case(
        self,
        permission_name: ApiPermissionsType,
        func: Callable[_P, Awaitable[_R]],
    ) -> Callable[_P, Awaitable[_R]]:
        @wraps(func)
        async def wrapped_use_case(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            """Wrap callback_mfa to handle session management."""
            await self.check_permission(permission_name)
            return await func(*args, **kwargs)

        return wrapped_use_case
