"""Kea DHCP manager for DHCP server managing.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv4Network

from .base import AbstractDHCPManager
from .dataclasses import (
    DHCPLease,
    DHCPOptionData,
    DHCPPool,
    DHCPReservation,
    DHCPSharedNetwork,
    DHCPSubnet,
)
from .exceptions import DHCPAPIError, DHCPEntryAddError, DHCPEntryUpdateError


class KeaDHCPManager(AbstractDHCPManager):
    """Kea DHCP server manager."""

    async def create_subnet(
        self,
        name: str,
        subnet: IPv4Network,
        pool: IPv4Network | str,
        default_gateway: str | None = None,
    ) -> None:
        """Create a new subnet."""
        option_data_dto = (
            [
                DHCPOptionData(name="routers", data=default_gateway),
            ]
            if default_gateway
            else []
        )

        pools_dto = [
            DHCPPool(
                pool=IPv4Network(pool),
            ),
        ]

        subnets_dto = [
            DHCPSubnet(
                subnet=IPv4Network(subnet),
                pools=pools_dto,
                option_data=option_data_dto,
            ),
        ]

        shared_network = [
            DHCPSharedNetwork(
                name=name,
                subnet4=subnets_dto,
            ),
        ]

        try:
            await self._api_repository.create_subnet(shared_network)
        except DHCPAPIError as e:
            raise DHCPEntryAddError(f"Failed to create subnet: {e}")

    async def delete_subnet(self, subnet_id: int) -> None:
        """Delete a subnet."""
        await self._api_repository.delete_subnet(subnet_id)

    async def get_subnets(self) -> list[DHCPSubnet]:
        """Get all subnets."""
        subnets = await self._api_repository.list_subnets()

        return (
            [
                await self._api_repository.get_subnet_by_id(s.id)
                for s in subnets
                if s and s.id
            ]
            if subnets
            else []
        )

    async def update_subnet(
        self,
        subnet_id: int,
        subnet: IPv4Network,
        pool: IPv4Network | str,
        default_gateway: str | None = None,
    ) -> None:
        """Update an existing subnet."""
        option_data_dto = (
            [
                DHCPOptionData(name="routers", data=default_gateway),
            ]
            if default_gateway
            else []
        )

        pools_dto = [
            DHCPPool(
                pool=IPv4Network(pool),
            ),
        ]

        subnets_dto = DHCPSubnet(
            id=subnet_id,
            subnet=subnet,
            pools=pools_dto,
            option_data=option_data_dto,
        )

        try:
            await self._api_repository.update_subnet(subnets_dto)
        except DHCPAPIError as e:
            raise DHCPEntryUpdateError(
                f"Failed to update subnet: {e}",
            )

    async def create_lease(
        self,
        mac_address: str,
        ip_address: IPv4Address,
    ) -> None:
        """Create a new lease."""
        lease = DHCPLease(
            mac_address=mac_address,
            ip_address=ip_address,
        )

        try:
            await self._api_repository.create_lease(lease)
        except DHCPAPIError as e:
            raise DHCPEntryAddError(f"Failed to create lease: {e}")

    async def release_lease(self, ip_address: IPv4Address) -> None:
        """Release a lease."""
        await self._api_repository.release_lease(ip_address)

    async def list_active_leases(
        self,
        subnet_id: int,
    ) -> list[DHCPLease]:
        """List active leases for a subnet."""
        return await self._api_repository.list_leases_by_subnet_id([subnet_id])

    async def find_lease(
        self,
        mac_address: str | None = None,
        hostname: str | None = None,
    ) -> DHCPLease:
        """Find a lease by MAC address or hostname."""
        if mac_address is not None:
            lease = await self._api_repository.get_lease_by_hw_address(
                mac_address,
            )
        elif hostname is not None:
            lease = await self._api_repository.get_lease_by_hostname(
                hostname,
            )
        else:
            raise DHCPAPIError(
                "Either MAC address or hostname must be provided.",
            )

        return lease

    async def add_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address,
        hostname: str | None = None,
    ) -> None:
        """Add a reservation for a MAC address."""
        reservation = DHCPReservation(
            hw_address=mac_address,
            ip_address=ip_address,
            hostname=hostname,
        )

        try:
            await self._api_repository.create_reservation(reservation)
        except DHCPAPIError as e:
            raise DHCPEntryAddError(
                f"Failed to add reservation: {e}",
            )

    async def delete_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address,
    ) -> None:
        """Delete a reservation for a MAC address."""
        reservation = DHCPReservation(
            ip_address=ip_address,
            identifier_type="hw-address",
            identifier=mac_address,
            operation_target="all",
        )

        await self._api_repository.delete_reservation(reservation)

    async def get_reservations(
        self,
        subnet_id: int,
    ) -> list[DHCPReservation]:
        """Get all reservations for a subnet."""
        return await self._api_repository.list_reservations(subnet_id)
