"""Abstract DHCP manager for DHCP server managing.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from enum import StrEnum

import httpx

DHCP_MANAGER_STATE_NAME = "DHCPManagerState"


class DHCPError(Exception):
    """DHCP manager error."""


class DHCPManagerState(StrEnum):
    """DHCP manager states."""

    NOT_CONFIGURED = "0"
    KEA_DHCP = "1"


class AbstractDHCPManager(ABC):
    """Abstract DHCP manager class."""

    _http_client: httpx.AsyncClient

    def __init__(
        self,
        http_client: httpx.AsyncClient,
    ) -> None:
        """Set up DHCP manager."""
        self._http_client = http_client

    @abstractmethod
    async def create_subnet(
        self,
        name: str,
        subnet: str,
        pool: str,
        default_gateway: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def delete_subnet(self, name: str) -> None: ...

    @abstractmethod
    async def get_subnets(
        self,
    ) -> dict[str, str] | list[dict[str, str]] | None: ...

    @abstractmethod
    async def update_subnet(
        self,
        subnet: str,
        netmask: str,
        default_gateway: str | None = None,
        options: dict[str, str] | None = None,
    ) -> None: ...

    @abstractmethod
    async def create_lease(
        self,
        mac_address,
        ip_address=None,
    ) -> None: ...

    @abstractmethod
    async def release_lease(self, ip_address: str) -> None: ...

    @abstractmethod
    async def list_active_leases(
        self,
        subnet: str,
    ) -> list[dict[str, str]] | None: ...

    @abstractmethod
    async def find_lease(
        self,
        mac_address: str | None = None,
        ip_address: str | None = None,
        hostname: str | None = None,
    ) -> dict[str, str] | None: ...

    @abstractmethod
    async def add_reservation(
        self,
        subnet: str,
        mac_address: str,
        ip_address: str | None = None,
        hostname: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def delete_reservation(
        self,
        subnet: str,
    ) -> None: ...

    @abstractmethod
    async def get_reservations(
        self,
        subnet: str,
    ) -> list[dict[str, str]] | None: ...
