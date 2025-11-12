"""Adapter for shadow api.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address
from typing import ParamSpec, TypeVar

from fastapi import status

from api.base_adapter import BaseAdapter
from ldap_protocol.auth import AuthManager, MFAManager
from ldap_protocol.auth.exceptions.mfa import (
    AuthenticationError,
    InvalidCredentialsError,
    NetworkPolicyError,
)
from ldap_protocol.identity.identity_exceptions import PasswordPolicyError

P = ParamSpec("P")
R = TypeVar("R")


class ShadowAdapter(BaseAdapter):
    """Adapter for shadow api with FastAPI."""

    _exceptions_map: dict[type[Exception], int] = {
        InvalidCredentialsError: status.HTTP_404_NOT_FOUND,
        NetworkPolicyError: status.HTTP_403_FORBIDDEN,
        AuthenticationError: status.HTTP_401_UNAUTHORIZED,
        PasswordPolicyError: status.HTTP_422_UNPROCESSABLE_ENTITY,
        PermissionError: status.HTTP_403_FORBIDDEN,
    }

    def __init__(
        self,
        mfa_manager: MFAManager,
        identity_manager: AuthManager,
    ) -> None:
        """Initialize the adapter."""
        self._mfa_manager = mfa_manager
        self._identity_manager = identity_manager

    async def proxy_request(
        self,
        principal: str,
        ip: IPv4Address,
    ) -> None:
        """Proxy a request to the shadow account."""
        return await self._mfa_manager.proxy_request(principal, ip)

    async def change_password(self, principal: str, new_password: str) -> None:
        """Change the password for a user."""
        return await self._identity_manager.sync_password_from_service(
            principal,
            new_password,
        )
