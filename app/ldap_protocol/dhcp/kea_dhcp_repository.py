"""Kea DHCP API repository implementation.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address
from typing import Any

import httpx

from .base import DHCPAPIRepository
from .dataclasses import (
    DHCPLease,
    DHCPOptionData,
    DHCPPool,
    DHCPReservation,
    DHCPSubnet,
)
from .enums import KeaDHCPCommands, KeaDHCPResultCodes
from .exceptions import (
    DHCPAPIError,
    DHCPConflictError,
    DHCPEntryNotFoundError,
    DHCPUnsupportedError,
)
from .retorts import (
    add_lease_retort,
    add_reservation_retort,
    add_subnet_retort,
    base_retort,
    delete_reservation_retort,
    delete_subnet_retort,
    get_all_reservations_retort,
    get_lease_by_hostname_retort,
    get_lease_by_hw_address_retort,
    get_subnet_retort,
    list_leases_retort,
    list_subnet_retort,
    release_lease_retort,
    update_subnet_retort,
)
from .schemas import (
    KeaDHCPAPILeaseRequest,
    KeaDHCPAPIReservationRequest,
    KeaDHCPAPISubnetRequest,
    KeaDHCPBaseAPIRequest,
)


class KeaDHCPAPIRepository(DHCPAPIRepository):
    """Repository for interacting with the DHCP API."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        """Initialize the repository with an HTTP client."""
        self._client = client

    @staticmethod
    def _validate_api_response(response: httpx.Response) -> None:
        """Validate API response."""
        if response.status_code != 200:
            raise DHCPAPIError(
                f"Failed to communicate with DHCP API: {response.text}",
            )

        result_code = response.json()[0].get("result")
        result_text = response.json()[0].get("text")

        match result_code:
            case KeaDHCPResultCodes.ERROR:
                raise DHCPAPIError(result_text)
            case KeaDHCPResultCodes.UNSUPPORTED:
                raise DHCPUnsupportedError(result_text)
            case KeaDHCPResultCodes.CONFLICT:
                raise DHCPConflictError(result_text)
            case KeaDHCPResultCodes.EMPTY:
                raise DHCPEntryNotFoundError(result_text)
            case KeaDHCPResultCodes.SUCCESS:
                pass

    async def _make_request(
        self,
        data: dict[str, Any],
        return_response: bool = False,
    ) -> httpx.Response | None:
        response = await self._client.post(
            url="/",
            json=data,
        )

        self._validate_api_response(response)

        return response if return_response else None

    async def create_subnet(
        self,
        subnet_dto: DHCPSubnet,
    ) -> None:
        """Add a new subnet."""
        data = add_subnet_retort.dump(
            KeaDHCPAPISubnetRequest(
                command=KeaDHCPCommands.SUBNET4_ADD,
                subnet4=[subnet_dto],
            ),
        )

        await self._make_request(data)

    async def update_subnet(
        self,
        subnet: DHCPSubnet,
    ) -> None:
        """Update an existing subnet."""
        data = update_subnet_retort.dump(
            KeaDHCPAPISubnetRequest(
                command=KeaDHCPCommands.SUBNET4_UPDATE,
                subnet4=[subnet],
            ),
        )

        await self._make_request(data)

    async def delete_subnet(
        self,
        subnet_id: int,
    ) -> None:
        """Delete a subnet."""
        data = delete_subnet_retort.dump(
            KeaDHCPAPISubnetRequest(
                command=KeaDHCPCommands.SUBNET4_DEL,
                subnet4=DHCPSubnet(
                    id=subnet_id,
                ),
            ),
        )

        await self._make_request(data)

    async def list_subnets(self) -> list[DHCPSubnet]:
        """List all subnets."""
        data = list_subnet_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.SUBNET4_LIST,
            ),
        )
        response = await self._make_request(
            data,
            return_response=True,
        )

        return (
            [
                DHCPSubnet(
                    id=item["id"],
                    subnet=item["subnet"],
                )
                for item in response.json()[0]
                .get("arguments")
                .get("subnets", [])
            ]
            if response is not None
            else []
        )

    async def get_subnet_by_id(self, subnet_id: int) -> DHCPSubnet:
        """Get a subnet by ID."""
        data = get_subnet_retort.dump(
            KeaDHCPAPISubnetRequest(
                command=KeaDHCPCommands.SUBNET4_GET,
                subnet4=DHCPSubnet(id=subnet_id),
            ),
        )

        response = await self._make_request(
            data,
            return_response=True,
        )

        subnet_data = (
            response.json()[0].get("arguments").get("subnet4")[0]
            if response
            else {}
        )

        return DHCPSubnet(
            id=subnet_data.get("id"),
            subnet=subnet_data.get("subnet"),
            pools=[
                DHCPPool(pool=pool["pool"])
                for pool in subnet_data.get("pools", [])
            ],
            valid_lifetime=subnet_data.get("valid-lifetime"),
            option_data=[
                DHCPOptionData(
                    name=option["name"],
                    data=option["data"],
                )
                for option in subnet_data.get("option-data", [])
            ]
            if subnet_data.get("option-data")
            else None,
        )

    async def create_lease(self, lease: DHCPLease) -> None:
        """Create a new lease."""
        data = add_lease_retort.dump(
            KeaDHCPAPILeaseRequest(
                command=KeaDHCPCommands.LEASE4_ADD,
                lease=lease,
            ),
        )

        await self._make_request(data)

    async def release_lease(self, ip_address: IPv4Address) -> None:
        """Release a lease by IP address."""
        data = release_lease_retort.dump(
            KeaDHCPAPILeaseRequest(
                command=KeaDHCPCommands.LEASE4_DEL,
                lease=DHCPLease(ip_address=ip_address),
            ),
        )

        await self._make_request(data)

    async def list_leases_by_subnet_id(
        self,
        subnet_ids: list[int],
    ) -> list[DHCPLease]:
        """List all leases."""
        data = list_leases_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.LEASE4_LIST,
                arguments=subnet_ids,
            ),
        )
        response = await self._make_request(
            data,
            return_response=True,
        )

        leases_data = (
            response.json()[0].get("arguments").get("leases")
            if response
            else None
        )

        return (
            [
                DHCPLease(
                    subnet_id=item.get("subnet-id"),
                    ip_address=item.get("ip-address"),
                    mac_address=item.get("hw-address"),
                    cltt=item.get("cltt"),
                    lifetime=item.get("valid-lft"),
                    hostname=item.get("hostname"),
                )
                for item in leases_data
            ]
            if leases_data
            else []
        )

    async def get_lease_by_hw_address(
        self,
        hw_address: str,
    ) -> DHCPLease:
        """Get a lease by hardware address."""
        data = get_lease_by_hw_address_retort.dump(
            KeaDHCPAPILeaseRequest(
                command=KeaDHCPCommands.LEASE4_GET_BY_HW_ADDRESS,
                lease=DHCPLease(mac_address=hw_address),
            ),
        )

        response = await self._make_request(
            data,
            return_response=True,
        )

        lease_data = (
            response.json()[0].get("arguments").get("leases")[0]
            if response
            else {}
        )

        return DHCPLease(
            id=lease_data.get("id"),
            subnet_id=lease_data.get("subnet-id"),
            ip_address=lease_data.get("ip-address"),
            mac_address=lease_data.get("hw-address"),
            cltt=lease_data.get("cltt"),
            lifetime=lease_data.get("valid-lft"),
            hostname=lease_data.get("hostname"),
        )

    async def get_lease_by_hostname(self, hostname: str) -> DHCPLease:
        """Get a lease by hostname."""
        data = get_lease_by_hostname_retort.dump(
            KeaDHCPAPILeaseRequest(
                command=KeaDHCPCommands.LEASE4_GET_BY_HOSTNAME,
                lease=DHCPLease(hostname=hostname),
            ),
        )

        response = await self._make_request(
            data,
            return_response=True,
        )

        lease_data = (
            response.json()[0].get("arguments").get("leases")[0]
            if response
            else {}
        )

        return DHCPLease(
            id=lease_data.get("id"),
            subnet_id=lease_data.get("subnet-id"),
            ip_address=lease_data.get("ip-address"),
            mac_address=lease_data.get("hw-address"),
            cltt=lease_data.get("cltt"),
            lifetime=lease_data.get("valid-lft"),
            hostname=lease_data.get("hostname"),
        )

    async def create_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None:
        """Create a new reservation."""
        data = add_reservation_retort.dump(
            KeaDHCPAPIReservationRequest(
                command=KeaDHCPCommands.RESERVATION_ADD,
                arguments=reservation,
            ),
        )

        await self._make_request(data)

    async def delete_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None:
        """Delete a reservation."""
        data = delete_reservation_retort.dump(
            KeaDHCPAPIReservationRequest(
                command=KeaDHCPCommands.RESERVATION_DEL,
                arguments=reservation,
            ),
        )

        await self._make_request(data)

    async def list_reservations(self, subnet_id: int) -> list[DHCPReservation]:
        """List all reservations."""
        data = get_all_reservations_retort.dump(
            KeaDHCPAPIReservationRequest(
                command=KeaDHCPCommands.RESERVATION_LIST,
                arguments=DHCPReservation(subnet_id=subnet_id),
            ),
        )
        response = await self._make_request(
            data,
            return_response=True,
        )

        reservations_data = (
            (response.json()[0].get("arguments").get("hosts"))
            if response
            else []
        )

        return [
            DHCPReservation(
                subnet_id=item.get("subnet-id"),
                ip_address=item.get("ip-address"),
                mac_address=item.get("hw-address"),
                hostname=item.get("hostname"),
            )
            for item in reservations_data
        ]

    async def write_config(self) -> None:
        """Write the current configuration to persistent storage."""
        data = base_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.CONFIG_WRITE,
                arguments={
                    "filename": "kea-dhcp4.conf",
                },
            ),
        )

        await self._make_request(data)

    async def set_config(self, config: dict[str, Any]) -> None:
        """Set the entire configuration."""
        data = base_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.CONFIG_SET,
                arguments=config,
            ),
        )

        await self._make_request(data)
