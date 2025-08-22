"""Abstract DHCP manager for DHCP server managing.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network

import httpx
from loguru import logger as loguru_logger

DHCP_MANAGER_STATE_NAME = "DHCPManagerState"

log = loguru_logger.bind(name="DHCPManager")

log.add(
    "logs/dhcpmanager_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "dhcpmanager",
    retention="10 days",
    rotation="1d",
    colorize=False,
)


class DHCPError(Exception):
    """DHCP manager error."""


class DHCPAPIError(Exception):
    """DHCP API error."""


class DHCPConnectionError(ConnectionError):
    """DHCP connection error."""


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
        subnet: IPv4Network,
        pool: IPv4Network | str,
        default_gateway: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def delete_subnet(self, name: str) -> None: ...

    @abstractmethod
    async def get_subnets(
        self,
    ) -> list[dict[str, str]] | None: ...

    @abstractmethod
    async def update_subnet(
        self,
        name: str,
        subnet: IPv4Network,
        pool: IPv4Network | str,
        default_gateway: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def create_lease(
        self,
        mac_address: str,
        ip_address: IPv4Address,
    ) -> None: ...

    @abstractmethod
    async def release_lease(self, ip_address: IPv4Address) -> None: ...

    @abstractmethod
    async def list_active_leases(
        self,
        subnet: IPv4Network,
    ) -> list[dict[str, str]] | None: ...

    @abstractmethod
    async def find_lease(
        self,
        mac_address: str | None = None,
        hostname: str | None = None,
    ) -> dict[str, str] | None: ...

    @abstractmethod
    async def add_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address | None = None,
        hostname: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def delete_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address,
    ) -> None: ...

    @abstractmethod
    async def get_reservations(
        self,
        subnet: IPv4Network,
    ) -> list[dict[str, str]] | None: ...
