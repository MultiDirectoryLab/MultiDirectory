"""Kea DHCP manager for DHCP server managing.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

import httpx

from .base import AbstractDHCPManager
from .dataclasses import DHCPLease, DHCPReservation, DHCPSubnet
from .enums import KeaDHCPCommands, KeaDHCPResultCodes
from .exceptions import (
    DHCPAPIError,
    DHCPConflictError,
    DHCPEntryAddError,
    DHCPEntryNotFoundError,
    DHCPEntryUpdateError,
    DHCPUnsupportedError,
)
from .schemas import KeaDHCPAPIRequest


class KeaDHCPManager(AbstractDHCPManager):
    """Kea DHCP server manager."""

    @staticmethod
    def _validate_api_response(response: httpx.Response) -> None:
        """Validate API response."""
        if response.status_code != 200:
            raise DHCPAPIError(
                f"Failed to communicate with DHCP API: {response.text}",
            )

        result_code = response.json().get("result")
        result_text = response.json().get("text")

        match result_code:
            case KeaDHCPResultCodes.ERROR:
                raise DHCPAPIError(result_text)
            case KeaDHCPResultCodes.UNSUPPORTED:
                raise DHCPUnsupportedError(result_text)
            case KeaDHCPResultCodes.CONFLICT:
                raise DHCPConflictError(result_text)
            case KeaDHCPResultCodes.EMPTY:
                raise DHCPEntryNotFoundError(result_text)

    async def create_subnet(
        self,
        name: str,
        subnet: IPv4Network,
        pool: IPv4Network | str,
        default_gateway: str | None = None,
    ) -> None:
        """Create a new subnet."""
        option_data = (
            [
                {
                    "name": "routers",
                    "data": default_gateway,
                },
            ]
            if default_gateway
            else []
        )

        subnet = [
            {
                "subnet": subnet,
                "pools": [{"pool": f"{pool}"}],
                "option-data": option_data,
            },
        ]

        shared_network = [
            {
                "name": name,
                "subnet4": subnet,
            },
        ]

        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.SUBNET4_ADD,
                arguments={"shared-networks": shared_network},
            ),
        )

        try:
            self._validate_api_response(response)
        except DHCPAPIError as e:
            raise DHCPEntryAddError(
                f"Failed to create subnet: {e}",
            )

        try:
            self._validate_api_response(response)
        except DHCPAPIError as e:
            raise DHCPEntryAddError(
                f"Failed to create subnet: {e}",
            )

    async def delete_subnet(self, subnet_id: int) -> None:
        """Delete a subnet."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.SUBNET4_DEL,
                arguments={"id": subnet_id},
            ),
        )

        self._validate_api_response(response)

    async def get_subnets(self) -> list[DHCPSubnet]:
        """Get all subnets."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(command=KeaDHCPCommands.SUBNET4_LIST),
        )

        self._validate_api_response(response)

        data = response.json()

        result = []

        for subnet in data.get("arguments").get("subnets", []):
            subnet_response = await self._http_client.post(
                "",
                json=KeaDHCPAPIRequest(
                    command=KeaDHCPCommands.SUBNET4_GET,
                    arguments={"id": subnet.get("id")},
                ),
            )

            self._validate_api_response(subnet_response)

            subnet = (
                subnet_response.json()
                .get("arguments", {})
                .get("subnets", [])[0]
            )

            result.append(
                DHCPSubnet(
                    id=subnet.get("id"),
                    subnet=subnet.get("subnet"),
                    pools=subnet.get("pools", [])[0].get("pool"),
                ),
            )

        return result

    async def update_subnet(
        self,
        subnet_id: int,
        subnet: IPv4Network,
        pool: IPv4Network | str,
        default_gateway: str | None = None,
    ) -> None:
        """Update an existing subnet."""
        option_data = (
            [
                {
                    "name": "routers",
                    "data": default_gateway,
                },
            ]
            if default_gateway
            else []
        )

        subnet = [
            {
                "id": subnet_id,
                "subnet": subnet,
                "pools": [{"pool": f"{pool}"}],
                "option-data": option_data,
            },
        ]

        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.SUBNET4_UPDATE,
                arguments={"subnet4": subnet},
            ),
        )

        try:
            self._validate_api_response(response)
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
        lease = {
            "hw-address": mac_address,
            "ip-address": ip_address,
        }

        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.LEASE4_ADD,
                arguments={"leases": [lease]},
            ),
        )

        try:
            self._validate_api_response(response)
        except DHCPAPIError as e:
            raise DHCPEntryAddError(f"Failed to create lease: {e}")

    async def release_lease(self, ip_address: IPv4Address) -> None:
        """Release a lease."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.LEASE4_DEL,
                arguments={"ip-address": ip_address},
            ),
        )

        self._validate_api_response(response)

    async def list_active_leases(
        self,
        subnet: IPv4Network,
    ) -> list[DHCPLease]:
        """List active leases for a subnet."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.LEASE4_LIST,
                arguments={"subnet": subnet},
            ),
        )

        self._validate_api_response(response)

        result = []

        for lease in response.json().get("arguments", {}).get("leases", []):
            result.append(
                DHCPLease(
                    id=lease.get("client_id"),
                    ip_address=lease.get("ip-address"),
                    mac_address=lease.get("hw-address"),
                    hostname=lease.get("hostname"),
                    expires=datetime.fromtimestamp(
                        lease.get("cltt") + lease.get("valid-lft"),
                    ),
                ),
            )

        return result

    async def find_lease(
        self,
        mac_address: str | None = None,
        hostname: str | None = None,
    ) -> DHCPLease:
        """Find a lease by MAC address, IP address, or hostname."""
        if mac_address is not None:
            response = await self._http_client.post(
                "",
                json=KeaDHCPAPIRequest(
                    command=KeaDHCPCommands.LEASE4_GET_BY_HW_ADDRESS,
                    arguments={"hw-address": mac_address},
                ),
            )
        elif hostname is not None:
            response = await self._http_client.post(
                "",
                json=KeaDHCPAPIRequest(
                    command=KeaDHCPCommands.LEASE4_GET_BY_HOSTNAME,
                    arguments={"hostname": hostname},
                ),
            )
        else:
            raise DHCPAPIError(
                "Either mac_address or hostname must be provided.",
            )

        self._validate_api_response(response)

        lease = response.json().get("arguments", {})

        return DHCPLease(
            id=lease.get("client_id"),
            ip_address=lease.get("ip-address"),
            mac_address=lease.get("hw-address"),
            hostname=lease.get("hostname"),
            expires=datetime.fromtimestamp(
                lease.get("cltt") + lease.get("valid-lft"),
            ),
        )

    async def add_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address | None = None,
        hostname: str | None = None,
    ) -> None:
        """Add a reservation for a MAC address."""
        reservation = {
            "hw-address": mac_address,
            "ip-address": ip_address,
            "hostname": hostname,
        }
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.RESERVATION_ADD,
                arguments={
                    "reservation": [reservation],
                    "operation-target": "all",
                },
            ),
        )

        try:
            self._validate_api_response(response)
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
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.RESERVATION_DEL,
                arguments={
                    "ip-address": ip_address,
                    "identifier-type": "hw-address",
                    "identifier": mac_address,
                    "operation-target": "all",
                },
            ),
        )

        self._validate_api_response(response)

    async def get_reservations(
        self,
        subnet_id: int,
    ) -> list[DHCPReservation]:
        """Get all reservations for a subnet."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.RESERVATION_LIST,
                arguments={
                    "subnet-id": subnet_id,
                    "operation-target": "all",
                },
            ),
        )

        self._validate_api_response(response)

        result = []

        for reservation in (
            response.json().get("arguments", {}).get("reservations", [])
        ):
            result.append(
                DHCPReservation(
                    id=reservation.get("reservation-id"),
                    ip_address=reservation.get("ip-address"),
                    mac_address=reservation.get("hw-address"),
                    hostname=reservation.get("hostname"),
                ),
            )

        return result
