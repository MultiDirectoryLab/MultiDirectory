"""Adapter for shadow api.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address

from api.base_adapter import BaseAdapter
from ldap_protocol.auth import AuthManager, MFAManager


class ShadowAdapter(BaseAdapter):
    """Adapter for shadow api with FastAPI."""

    def __init__(
        self,
        mfa_manager: MFAManager,
        auth_manager: AuthManager,
    ) -> None:
        """Initialize the adapter."""
        self._mfa_manager = mfa_manager
        self._auth_manager = auth_manager

    async def proxy_request(
        self,
        principal: str,
        ip: IPv4Address,
    ) -> None:
        """Proxy a request to the shadow account."""
        return await self._mfa_manager.proxy_request(principal, ip)

    async def change_password(self, principal: str, new_password: str) -> None:
        """Change the password for a user."""
        return await self._auth_manager.sync_password_from_service(
            principal,
            new_password,
        )
