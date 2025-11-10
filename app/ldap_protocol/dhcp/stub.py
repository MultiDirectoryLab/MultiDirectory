"""Stub DHCP manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address
from typing import NoReturn

from .base import AbstractDHCPManager, DHCPAPIRepository
from .dataclasses import DHCPLease, DHCPReservation, DHCPSubnet
from .exceptions import DHCPAPIError
from .utils import logger_wraps


class StubDHCPAPIRepository(DHCPAPIRepository):
    """Stub DHCP API repository class."""

    @logger_wraps(is_stub=True)
    async def create_subnet(
        self,
        subnet_dto: DHCPSubnet,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_subnet(self, subnet_id: int) -> None: ...

    @logger_wraps(is_stub=True)
    async def list_subnets(self) -> NoReturn:
        raise DHCPAPIError

    @logger_wraps(is_stub=True)
    async def get_subnet_by_id(
        self,
        subnet_id: int,  # noqa: ARG002
    ) -> NoReturn:
        raise DHCPAPIError

    @logger_wraps(is_stub=True)
    async def update_subnet(self, subnet_dto: DHCPSubnet) -> None: ...

    @logger_wraps(is_stub=True)
    async def create_lease(self, lease: DHCPLease) -> None: ...

    @logger_wraps(is_stub=True)
    async def release_lease(self, ip_address: IPv4Address) -> None: ...

    @logger_wraps(is_stub=True)
    async def list_leases_by_subnet_id(
        self,
        subnet_ids: list[int],  # noqa: ARG002
    ) -> NoReturn:
        raise DHCPAPIError

    @logger_wraps(is_stub=True)
    async def get_lease_by_hw_address(
        self,
        hw_address: str,  # noqa: ARG002
    ) -> NoReturn:
        raise DHCPAPIError

    @logger_wraps(is_stub=True)
    async def get_lease_by_hostname(
        self,
        hostname: str,  # noqa: ARG002
    ) -> NoReturn:
        raise DHCPAPIError

    @logger_wraps(is_stub=True)
    async def create_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_reservation(self, reservation: DHCPReservation) -> None:
        """Update a reservation."""

    @logger_wraps(is_stub=True)
    async def delete_reservation(self, reservation: DHCPReservation) -> None:
        """Delete a reservation."""

    @logger_wraps(is_stub=True)
    async def list_reservations(
        self,
        subnet_id: int,  # noqa: ARG002
    ) -> NoReturn:
        raise DHCPAPIError

    @logger_wraps(is_stub=True)
    async def write_config(self) -> None:
        """Write the DHCP server configuration to apply changes."""


class StubDHCPManager(AbstractDHCPManager):
    """Stub DHCP manager class."""

    @logger_wraps(is_stub=True)
    async def create_subnet(
        self,
        subnet_dto: DHCPSubnet,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_subnet(self, subnet_id: int) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_subnets(
        self,
    ) -> NoReturn:
        raise DHCPAPIError

    @logger_wraps(is_stub=True)
    async def update_subnet(
        self,
        subnet_dto: DHCPSubnet,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def create_lease(
        self,
        lease: DHCPLease,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def release_lease(self, ip_address: IPv4Address) -> None: ...

    @logger_wraps(is_stub=True)
    async def list_active_leases(
        self,
        subnet_id: int,  # noqa: ARG002
    ) -> NoReturn:
        raise DHCPAPIError

    @logger_wraps(is_stub=True)
    async def find_lease(
        self,
        mac_address: str | None = None,  # noqa: ARG002
        hostname: str | None = None,  # noqa: ARG002
    ) -> NoReturn:
        raise DHCPAPIError

    @logger_wraps(is_stub=True)
    async def lease_to_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def add_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address,
        subnet_id: int,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_reservations(
        self,
        subnet_id: int,  # noqa: ARG002
    ) -> NoReturn:
        raise DHCPAPIError
