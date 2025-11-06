"""Kea DHCP manager for DHCP server managing.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address

from .base import AbstractDHCPManager
from .dataclasses import DHCPLease, DHCPReservation, DHCPSubnet
from .exceptions import (
    DHCPAPIError,
    DHCPEntryAddError,
    DHCPEntryDeleteError,
    DHCPEntryNotFoundError,
    DHCPEntryUpdateError,
    DHCPError,
    DHCPValidatonError,
)


class KeaDHCPManager(AbstractDHCPManager):
    """Kea DHCP server manager."""

    async def create_subnet(
        self,
        subnet_dto: DHCPSubnet,
    ) -> None:
        """Create a new subnet."""
        subnet_dto.id = await self._get_new_subnet_id()
        try:
            await self._api_repository.create_subnet(subnet_dto)
            await self._api_repository.write_config()
        except DHCPAPIError as e:
            raise DHCPEntryAddError(f"Failed to create subnet: {e}")

    async def delete_subnet(self, subnet_id: int) -> None:
        """Delete a subnet."""
        try:
            await self._api_repository.delete_subnet(subnet_id)
            await self._api_repository.write_config()
        except DHCPAPIError as e:
            raise DHCPEntryDeleteError(f"Failed to delete subnet: {e}")

    async def get_subnets(self) -> list[DHCPSubnet]:
        """Get all subnets."""
        try:
            subnets = await self._api_repository.list_subnets()
        except DHCPEntryNotFoundError:
            return []

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
        subnet_dto: DHCPSubnet,
    ) -> None:
        """Update an existing subnet."""
        try:
            await self._api_repository.update_subnet(subnet_dto)
            await self._api_repository.write_config()
        except DHCPAPIError as e:
            raise DHCPEntryUpdateError(
                f"Failed to update subnet: {e}",
            )

    async def create_lease(
        self,
        lease: DHCPLease,
    ) -> None:
        """Create a new lease."""
        try:
            await self._api_repository.create_lease(lease)
        except DHCPAPIError as e:
            raise DHCPEntryAddError(f"Failed to create lease: {e}")

    async def release_lease(self, ip_address: IPv4Address) -> None:
        """Release a lease."""
        try:
            await self._api_repository.release_lease(ip_address)
        except DHCPAPIError as e:
            raise DHCPEntryDeleteError(f"Failed to release lease: {e}")

    async def list_active_leases(
        self,
        subnet_id: int,
    ) -> list[DHCPLease]:
        """List active leases for a subnet."""
        try:
            return await self._api_repository.list_leases_by_subnet_id(
                [subnet_id],
            )
        except DHCPEntryNotFoundError:
            return []

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

    async def lease_to_reservation(self, reservation: DHCPReservation) -> None:
        """Transform lease to reservation.

        Transoformation can only be done via delete -> create
        due to limitation of the Kea DHCP API.
        """
        if reservation.ip_address is None:
            raise DHCPValidatonError("IP address must be specified")

        try:
            await self._api_repository.release_lease(reservation.ip_address)
        except DHCPAPIError as e:
            raise DHCPEntryDeleteError(f"Failed to release lease: {e}")

        try:
            await self._api_repository.create_reservation(reservation)
        except DHCPError as e:
            await self._api_repository.create_lease(
                DHCPLease(
                    subnet_id=reservation.subnet_id,
                    ip_address=reservation.ip_address,
                    mac_address=reservation.mac_address,
                    hostname=reservation.hostname,
                ),
            )

            raise DHCPEntryAddError(
                f"Failed to add reservation: {e}",
            )

    async def add_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None:
        """Add a reservation for a MAC address."""
        try:
            await self._api_repository.create_reservation(reservation)
            await self._api_repository.write_config()
        except DHCPAPIError as e:
            raise DHCPEntryAddError(
                f"Failed to add reservation: {e}",
            )

    async def delete_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address,
        subnet_id: int,
    ) -> None:
        """Delete a reservation for a MAC address."""
        reservation = DHCPReservation(
            ip_address=ip_address,
            subnet_id=subnet_id,
            identifier=mac_address,
        )
        try:
            await self._api_repository.delete_reservation(reservation)
            await self._api_repository.write_config()
        except DHCPAPIError as e:
            raise DHCPEntryDeleteError(
                f"Failed to delete reservation: {e}",
            )

    async def get_reservations(
        self,
        subnet_id: int,
    ) -> list[DHCPReservation]:
        """Get all reservations for a subnet."""
        try:
            return await self._api_repository.list_reservations(subnet_id)
        except DHCPEntryNotFoundError:
            return []

    async def _get_new_subnet_id(self) -> int:
        try:
            subnets = await self._api_repository.list_subnets()
        except DHCPEntryNotFoundError:
            return 1
        return max(s.id for s in subnets if s.id) + 1
