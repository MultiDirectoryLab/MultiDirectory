"""Adapter for Kea DHCP server.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address

from fastapi import status

from api.base_adapter import BaseAdapter
from ldap_protocol.dhcp import (
    AbstractDHCPManager,
    DHCPAPIError,
    DHCPChangeStateSchemaRequest,
    DHCPEntryAddError,
    DHCPEntryDeleteError,
    DHCPEntryNotFoundError,
    DHCPEntryUpdateError,
    DHCPLeaseSchemaRequest,
    DHCPLeaseSchemaResponse,
    DHCPReservationSchemaRequest,
    DHCPReservationSchemaResponse,
    DHCPStateSchemaResponse,
    DHCPSubnetSchemaAddRequest,
    DHCPSubnetSchemaResponse,
    DHCPValidatonError,
)
from ldap_protocol.dhcp.dataclasses import (
    DHCPLease,
    DHCPOptionData,
    DHCPPool,
    DHCPReservation,
    DHCPSubnet,
)


class DHCPAdapter(BaseAdapter[AbstractDHCPManager]):
    """Adapter for DHCP management using KeaDHCPManager."""

    _exceptions_map: dict[type[Exception], int] = {
        DHCPEntryNotFoundError: status.HTTP_404_NOT_FOUND,
        DHCPEntryDeleteError: status.HTTP_409_CONFLICT,
        DHCPEntryAddError: status.HTTP_409_CONFLICT,
        DHCPEntryUpdateError: status.HTTP_409_CONFLICT,
        DHCPAPIError: status.HTTP_400_BAD_REQUEST,
        DHCPValidatonError: status.HTTP_422_UNPROCESSABLE_ENTITY,
    }

    async def create_subnet(
        self,
        subnet_data: DHCPSubnetSchemaAddRequest,
    ) -> None:
        """Create a new subnet."""
        option_data_dto = (
            [
                DHCPOptionData(
                    name="routers",
                    data=subnet_data.default_gateway,
                ),
            ]
            if subnet_data.default_gateway
            else []
        )

        pools_dto = [
            DHCPPool(
                pool=subnet_data.pool,
            ),
        ]

        subnets_dto = DHCPSubnet(
            subnet=subnet_data.subnet,
            pools=pools_dto,
            valid_lifetime=subnet_data.valid_lifetime,
            option_data=option_data_dto,
        )
        return await self._service.create_subnet(subnets_dto)

    async def delete_subnet(self, subnet_id: int) -> None:
        """Delete a subnet."""
        return await self._service.delete_subnet(subnet_id)

    async def get_subnets(self) -> list[DHCPSubnetSchemaResponse]:
        """Get all subnets."""
        return [
            DHCPSubnetSchemaResponse(
                id=subnet.id,
                subnet=subnet.subnet,
                pool=[p.pool for p in subnet.pools] if subnet.pools else [],
                valid_lifetime=subnet.valid_lifetime,
                default_gateway=subnet.option_data[0].data
                if subnet.option_data
                else None,
            )
            for subnet in await self._service.get_subnets()
        ]

    async def update_subnet(
        self,
        subnet_id: int,
        subnet_data: DHCPSubnetSchemaAddRequest,
    ) -> None:
        """Update a subnet."""
        option_data_dto = (
            [
                DHCPOptionData(
                    name="routers",
                    data=subnet_data.default_gateway,
                ),
            ]
            if subnet_data.default_gateway
            else []
        )

        pools_dto = [
            DHCPPool(
                pool=subnet_data.pool,
            ),
        ]

        subnets_dto = DHCPSubnet(
            id=subnet_id,
            subnet=subnet_data.subnet,
            pools=pools_dto,
            valid_lifetime=subnet_data.valid_lifetime,
            option_data=option_data_dto,
        )

        return await self._service.update_subnet(subnets_dto)

    async def create_lease(
        self,
        lease_data: DHCPLeaseSchemaRequest,
    ) -> None:
        """Create a new lease."""
        return await self._service.create_lease(
            DHCPLease(
                subnet_id=lease_data.subnet_id,
                ip_address=lease_data.ip_address,
                mac_address=lease_data.mac_address,
                hostname=lease_data.hostname,
            ),
        )

    async def release_lease(self, ip_address: IPv4Address) -> None:
        """Delete a lease."""
        return await self._service.release_lease(ip_address)

    async def list_active_leases(
        self,
        subnet_id: int,
    ) -> list[DHCPLeaseSchemaResponse]:
        """Get all leases."""
        return [
            DHCPLeaseSchemaResponse(
                subnet_id=lease.subnet_id,
                ip_address=lease.ip_address,
                mac_address=lease.mac_address,
                hostname=lease.hostname,
                expires=lease.expires,
            )
            for lease in await self._service.list_active_leases(subnet_id)
        ]

    async def find_lease(
        self,
        mac_address: str | None = None,
        hostname: str | None = None,
    ) -> DHCPLeaseSchemaResponse | None:
        """Find a lease by MAC address or hostname."""
        lease = await self._service.find_lease(
            mac_address=mac_address,
            hostname=hostname,
        )
        return (
            DHCPLeaseSchemaResponse(
                subnet_id=lease.subnet_id,
                ip_address=lease.ip_address,
                mac_address=lease.mac_address,
                hostname=lease.hostname,
                expires=lease.expires,
            )
            if lease
            else None
        )

    async def lease_to_reservation(
        self,
        data: DHCPReservationSchemaRequest,
    ) -> None:
        """Transform lease to reservation."""
        await self._service.lease_to_reservation(
            DHCPReservation(
                subnet_id=data.subnet_id,
                ip_address=data.ip_address,
                mac_address=data.mac_address,
                hostname=data.hostname,
            ),
        )

    async def add_reservation(
        self,
        reservation_data: DHCPReservationSchemaRequest,
    ) -> None:
        """Add a new reservation."""
        return await self._service.add_reservation(
            DHCPReservation(
                subnet_id=reservation_data.subnet_id,
                ip_address=reservation_data.ip_address,
                mac_address=reservation_data.mac_address,
                hostname=reservation_data.hostname,
            ),
        )

    async def delete_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address,
        subnet_id: int,
    ) -> None:
        """Delete a reservation."""
        return await self._service.delete_reservation(
            mac_address,
            ip_address,
            subnet_id,
        )

    async def get_reservations(
        self,
        subnet_id: int,
    ) -> list[DHCPReservationSchemaResponse]:
        """Get all reservations."""
        return [
            DHCPReservationSchemaResponse(
                subnet_id=reservation.subnet_id,
                ip_address=reservation.ip_address,
                mac_address=reservation.mac_address,
                hostname=reservation.hostname,
            )
            for reservation in await self._service.get_reservations(subnet_id)
        ]

    async def change_state(
        self,
        state_data: DHCPChangeStateSchemaRequest,
    ) -> None:
        """Configure the DHCP server."""
        await self._service.change_state(state_data.dhcp_manager_state)

    async def get_state(self) -> DHCPStateSchemaResponse:
        """Get the current state of the DHCP server."""
        return DHCPStateSchemaResponse(
            dhcp_manager_state=await self._service.get_state(),
        )
