"""Abstract DHCP manager for DHCP server managing.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from ipaddress import IPv4Address

import httpx
from loguru import logger as loguru_logger

from abstract_dao import AbstractService

from .dataclasses import DHCPLease, DHCPReservation, DHCPSubnet
from .dhcp_manager_repository import DHCPManagerRepository
from .enums import DHCPManagerState

log = loguru_logger.bind(name="DHCPManager")

log.add(
    "logs/dhcpmanager_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "DHCPmanager",
    retention="10 days",
    rotation="1d",
    colorize=False,
)


class DHCPAPIRepository(ABC):
    """Abstract DHCP API repository."""

    _client: httpx.AsyncClient

    def __init__(self, client: httpx.AsyncClient) -> None:
        """Initialize the repository with an HTTP client."""
        self._client = client

    @abstractmethod
    async def create_subnet(
        self,
        subnet_dto: DHCPSubnet,
    ) -> None:
        """Create a new subnet."""

    @abstractmethod
    async def delete_subnet(self, subnet_id: int) -> None:
        """Delete a subnet."""

    @abstractmethod
    async def list_subnets(self) -> list[DHCPSubnet]:
        """Get all subnets."""

    @abstractmethod
    async def get_subnet_by_id(self, subnet_id: int) -> DHCPSubnet:
        """Get a subnet by ID."""

    @abstractmethod
    async def update_subnet(self, subnet_dto: DHCPSubnet) -> None:
        """Update existing subnet."""

    @abstractmethod
    async def create_lease(self, lease: DHCPLease) -> None:
        """Create a new lease."""

    @abstractmethod
    async def release_lease(self, ip_address: IPv4Address) -> None:
        """Release a lease."""

    @abstractmethod
    async def list_leases_by_subnet_id(
        self,
        subnet_ids: list[int],
    ) -> list[DHCPLease]:
        """List all active leases for a given subnet."""

    @abstractmethod
    async def get_lease_by_hw_address(
        self,
        hw_address: str,
    ) -> DHCPLease:
        """Get a lease by hardware address."""

    @abstractmethod
    async def get_lease_by_hostname(self, hostname: str) -> DHCPLease:
        """Get a lease by hostname."""

    @abstractmethod
    async def create_reservation(self, reservation: DHCPReservation) -> None:
        """Create a new reservation."""

    @abstractmethod
    async def update_reservation(self, reservation: DHCPReservation) -> None:
        """Update a reservation."""

    @abstractmethod
    async def delete_reservation(self, reservation: DHCPReservation) -> None:
        """Delete a reservation."""

    @abstractmethod
    async def list_reservations(self, subnet_id: int) -> list[DHCPReservation]:
        """List all reservations for a subnet."""

    @abstractmethod
    async def write_config(self) -> None:
        """Write the DHCP server configuration to apply changes."""


class AbstractDHCPManager(AbstractService):
    """Abstract DHCP manager class."""

    _api_repository: DHCPAPIRepository
    _manager_repository: DHCPManagerRepository

    def __init__(
        self,
        kea_dhcp_repository: DHCPAPIRepository,
        dhcp_manager_repository: DHCPManagerRepository,
    ) -> None:
        """Initialize Kea DHCP manager."""
        self._api_repository = kea_dhcp_repository
        self._manager_repository = dhcp_manager_repository

    async def change_state(self, dhcp_state: DHCPManagerState) -> None:
        """Change DHCP service state."""
        await self._manager_repository.change_state(
            dhcp_state,
        )

    async def get_state(self) -> DHCPManagerState:
        """Get current DHCP service state."""
        return await self._manager_repository.ensure_state()

    @abstractmethod
    async def create_subnet(
        self,
        subnet_dto: DHCPSubnet,
    ) -> None: ...

    @abstractmethod
    async def delete_subnet(self, subnet_id: int) -> None: ...

    @abstractmethod
    async def get_subnets(
        self,
    ) -> list[DHCPSubnet]: ...

    @abstractmethod
    async def update_subnet(
        self,
        subnet_dto: DHCPSubnet,
    ) -> None: ...

    @abstractmethod
    async def create_lease(
        self,
        lease: DHCPLease,
    ) -> None: ...

    @abstractmethod
    async def release_lease(self, ip_address: IPv4Address) -> None: ...

    @abstractmethod
    async def list_active_leases(
        self,
        subnet_id: int,
    ) -> list[DHCPLease]: ...

    @abstractmethod
    async def find_lease(
        self,
        mac_address: str | None = None,
        hostname: str | None = None,
    ) -> DHCPLease: ...

    @abstractmethod
    async def lease_to_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None: ...

    @abstractmethod
    async def add_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None: ...

    @abstractmethod
    async def update_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None: ...

    @abstractmethod
    async def delete_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address,
        subnet_id: int,
    ) -> None: ...

    @abstractmethod
    async def get_reservations(
        self,
        subnet_id: int,
    ) -> list[DHCPReservation]: ...
