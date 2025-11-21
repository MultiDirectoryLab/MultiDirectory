"""Protocol for AuthorizationProvider."""

from typing import Awaitable, Callable, ParamSpec, Protocol, TypeVar

from enums import AuthorizationRules

_P = ParamSpec("_P")
_R = TypeVar("_R")


class AuthorizationProviderProtocol(Protocol):
    """Authorization provider protocol."""

    async def _has_permission(
        self,
        permission: AuthorizationRules,
    ) -> None: ...

    async def check_permission(
        self,
        permission: AuthorizationRules,
    ) -> None: ...

    def wrap_use_case(
        self,
        permission_name: AuthorizationRules,
        func: Callable[_P, Awaitable[_R]],
    ) -> None: ...
