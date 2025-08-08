"""Adapter for shadow api.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address
from typing import Awaitable, Callable, ParamSpec, TypeVar

from fastapi import HTTPException, status

from api.exceptions.auth import PasswordPolicyError
from api.exceptions.mfa import (
    AuthenticationError,
    InvalidCredentialsError,
    NetworkPolicyError,
)
from ldap_protocol.identity import IdentityManager, MFAManager

P = ParamSpec("P")
R = TypeVar("R")


class ShadowAdapter:
    """Adapter for shadow api with FastAPI."""

    def __init__(
        self,
        mfa_manager: MFAManager,
        identity_manager: IdentityManager,
    ) -> None:
        """Initialize the adapter."""
        self._mfa_manager = mfa_manager
        self._identity_manager = identity_manager

    async def _sc(
        self,
        func: Callable[P, Awaitable[R]],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        try:
            return await func(*args, **kwargs)
        except InvalidCredentialsError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
            )
        except NetworkPolicyError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
            )
        except AuthenticationError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        except PasswordPolicyError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

    async def proxy_request(
        self,
        principal: str,
        ip: IPv4Address,
    ) -> None:
        """Proxy a request to the shadow account."""
        return await self._sc(
            self._mfa_manager.proxy_request,
            principal,
            ip,
        )

    async def change_password(self, principal: str, new_password: str) -> None:
        """Change the password for a user."""
        return await self._sc(
            self._identity_manager.change_password,
            principal,
            new_password,
        )
