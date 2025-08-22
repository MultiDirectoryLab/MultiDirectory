"""Kea DHCP manager for DHCP server managing.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel

from .base import AbstractDHCPManager, DHCPError


class KeaDHCPCommands(StrEnum):
    """Kea DHCP API commands."""

    NETWORK4_ADD = "network4-add"
    NETWORK4_DEL = "network4-del"
    NETWORK4_LIST = "network4-list"
    NETWORK4_GET = "network4-get"
    LEASE4_ADD = "lease4-add"
    LEASE4_DEL = "lease4-del"
    LEASE4_LIST = "lease4-list"
    LEASE4_GET_BY_HW_ADDRESS = "lease4-get-by-hw-address"
    LEASE4_GET_BY_HOSTNAME = "lease4-get-by-hostname"
    RESERVATION_ADD = "reservation-add"
    RESERVATION_DEL = "reservation-del"
    RESERVATION_LIST = "reservation-list"


class KeaDHCPAPIRequest(BaseModel):
    """Base request for Kea DHCP API."""

    command: str
    arguments: dict | None = None


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
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.NETWORK4_ADD,
                arguments={
                    "shared-networks": [
                        {
                            "name": name,
                            "subnet4": [
                                {
                                    "subnet": subnet,
                                    "pools": [{"pool": f"{pool}"}],
                                    "option-data": [
                                        {
                                            "name": "routers",
                                            "data": default_gateway,
                                        },
                                    ]
                                    if default_gateway
                                    else [],
                                },
                            ],
                        },
                    ],
                },
            ),
        )

        if (
            response.status_code != 200
            or not response.json().get("result") == 0
        ):
            raise DHCPError(f"Failed to create subnet: {response.text}")

    async def delete_subnet(self, name: str) -> None:
        """Delete a subnet."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.NETWORK4_DEL,
                arguments={"name": name},
            ),
        )

        if response.status_code != 200 or response.json().get("result") != 0:
            raise DHCPError(f"Failed to delete subnet: {response.text}")

    async def get_subnets(self) -> list[dict[str, str]] | None:
        """Get all subnets."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(command=KeaDHCPCommands.NETWORK4_LIST),
        )

        if response.status_code != 200:
            raise DHCPError(f"Failed to get subnets: {response.text}")

        data = response.json()
        if data.get("result") != 0:
            return None

        result = []

        for shared_network in data.get("arguments").get("shared-networks"):
            response = await self._http_client.post(
                "",
                json=KeaDHCPAPIRequest(
                    command=KeaDHCPCommands.NETWORK4_GET,
                    arguments={"name": shared_network["name"]},
                ),
            )

            if (
                response.status_code != 200
                or response.json().get("result") != 0
            ):
                continue

            result.append(
                response.json().get("arguments").get("shared-networks")[0],
            )

        return result

    async def update_subnet(
        self,
        name: str,
        subnet: IPv4Network,
        pool: IPv4Network | str,
        default_gateway: str | None = None,
    ) -> None:
        """Update an existing subnet."""
        await self.delete_subnet(name)
        await self.create_subnet(name, subnet, pool, default_gateway)

    async def create_lease(
        self,
        mac_address: str,
        ip_address: IPv4Address = None,
    ):
        """Create a new lease."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.LEASE4_ADD,
                arguments={
                    "leases": [
                        {
                            "hw-address": mac_address,
                            "ip-address": ip_address,
                        },
                    ],
                },
            ),
        )

        if response.status_code != 200 or response.json().get("result") != 0:
            raise DHCPError(f"Failed to create lease: {response.text}")

    async def release_lease(self, ip_address: IPv4Address) -> None:
        """Release a lease."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.LEASE4_DEL,
                arguments={"ip-address": ip_address},
            ),
        )

        if response.status_code != 200 or response.json().get("result") != 0:
            raise DHCPError(f"Failed to release lease: {response.text}")

    async def list_active_leases(
        self,
        subnet: IPv4Network,
    ) -> list[dict[str, str]] | None:
        """List active leases for a subnet."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.LEASE4_LIST,
                arguments={"subnet": subnet},
            ),
        )

        if response.status_code != 200 or response.json().get("result") != 0:
            raise DHCPError(f"Failed to list active leases: {response.text}")

        result = []

        for lease in response.json().get("arguments", {}).get("leases", []):
            result.append({lease["hw-address"]: lease["ip-address"]})

        return result

    async def find_lease(
        self,
        mac_address: str | None = None,
        hostname: str | None = None,
    ) -> dict[str, str] | None:
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
            raise DHCPError(
                "Either mac_address or hostname must be provided.",
            )

        if response.status_code != 200 or response.json().get("result") != 0:
            raise DHCPError(f"Failed to find lease: {response.text}")

        return {
            "mac_address": response.json()
            .get("arguments", {})
            .get("leases", [{}])[0]
            .get("hw-address"),
            "ip_address": response.json()
            .get("arguments", {})
            .get("leases", [{}])[0]
            .get("ip-address"),
        }

    async def add_reservation(
        self,
        mac_address: str,
        ip_address: IPv4Address | None = None,
        hostname: str | None = None,
    ) -> None:
        """Add a reservation for a MAC address."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.RESERVATION_ADD,
                arguments={
                    "reservation": [
                        {
                            "hw-address": mac_address,
                            "ip-address": ip_address,
                            "hostname": hostname,
                        },
                    ],
                    "operation-target": "all",
                },
            ),
        )

        if response.status_code != 200 or response.json().get("result") != 0:
            raise DHCPError(f"Failed to add reservation: {response.text}")

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

        if response.status_code != 200 or response.json().get("result") != 0:
            raise DHCPError(f"Failed to delete reservation: {response.text}")

    async def get_reservations(
        self,
        subnet: IPv4Network,
    ) -> list[dict[str, str]] | None:
        """Get all reservations for a subnet."""
        response = await self._http_client.post(
            "",
            json=KeaDHCPAPIRequest(
                command=KeaDHCPCommands.RESERVATION_LIST,
                arguments={
                    "subnet-id": subnet,
                    "operation-target": "all",
                },
            ),
        )

        if response.status_code != 200 or response.json().get("result") != 0:
            raise DHCPError(f"Failed to get reservations: {response.text}")

        return response.json().get("arguments", {}).get("reservations", [])
