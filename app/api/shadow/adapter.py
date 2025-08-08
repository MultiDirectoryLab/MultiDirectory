"""Adapter for ShadowManager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address
from typing import Awaitable, Callable, ParamSpec, TypeVar

from fastapi import HTTPException, status

from ldap_protocol.shadow_manager import (
    AuthenticationError,
    NetworkPolicyNotFoundError,
    PasswordPolicyError,
    ShadowManager,
    UserNotFoundError,
)

P = ParamSpec("P")
R = TypeVar("R")


class ShadowAdapter:
    """Adapter for using ShadowManager with FastAPI."""

    def __init__(self, shadow_manager: ShadowManager):
        """Initialize the adapter with a domain ShadowManager instance.

        :param shadow_manager: ShadowManager instance (domain logic)
        """
        self._manager = shadow_manager

    async def _sc(
        self,
        func: Callable[P, Awaitable[R]],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        try:
            return await func(*args, **kwargs)
        except UserNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        except NetworkPolicyNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Network policy not found",
            )
        except AuthenticationError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
            )
        except PasswordPolicyError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Password policy validation failed",
            )

    async def proxy_request(
        self,
        principal: str,
        ip: IPv4Address,
    ) -> None:
        """Proxy a request to the shadow account."""
        return await self._sc(
            self._manager.proxy_request,
            principal,
            ip,
        )

    async def change_password(self, principal: str, new_password: str) -> None:
        """Change the password for a user."""
        return await self._sc(
            self._manager.change_password,
            principal,
            new_password,
        )
