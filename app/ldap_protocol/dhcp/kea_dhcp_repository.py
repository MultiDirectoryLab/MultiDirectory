"""Kea DHCP API repository implementation.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address
from typing import Any

import httpx
from adaptix import Retort, name_mapping

from .base import DHCPAPIRepository
from .dataclasses import (
    DHCPLease,
    DHCPOptionData,
    DHCPPool,
    DHCPReservation,
    DHCPSharedNetwork,
    DHCPSubnet,
)
from .enums import KeaDHCPCommands, KeaDHCPResultCodes
from .exceptions import (
    DHCPAPIError,
    DHCPConflictError,
    DHCPEntryNotFoundError,
    DHCPUnsupportedError,
)
from .schemas import KeaDHCPBaseAPIRequest

base_retort = Retort()

add_subnet_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPSubnet,
            map={
                "option_data": "option-data",
            },
        ),
        name_mapping(
            DHCPSharedNetwork,
            map=[
                (DHCPSharedNetwork, ("arguments", "shared-network", ...)),
            ],
        ),
    ],
)

update_subnet_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPSubnet,
            map={
                "option_data": "option-data",
            },
        ),
        name_mapping(
            DHCPSubnet,
            map=[
                (DHCPSubnet, ("arguments", "subnet4", ...)),
            ],
            as_list=True,
        ),
    ],
)

delete_subnet_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPSubnet,
            only="id",
        ),
    ],
)

list_subnet_retort = base_retort.extend(
    recipe=[
        name_mapping(
            KeaDHCPBaseAPIRequest,
            only="command",
        ),
    ],
)

get_subnet_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPSubnet,
            only="id",
        ),
    ],
)

add_lease_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPLease,
            only=[
                "ip_address",
                "hw_address",
            ],
            map={
                "ip_address": "ip-address",
                "hw_address": "hw-address",
            },
        ),
    ],
)

release_lease_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPLease,
            only="ip_address",
            map={
                "ip_address": "ip-address",
            },
        ),
    ],
)

list_leases_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPSubnet,
            only="id",
            map=[
                (DHCPSubnet, ("arguments", "subnets", ...)),
            ],
            as_list=True,
        ),
    ],
)

get_lease_by_hw_address_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPLease,
            only="hw_address",
            map={
                "hw_address": "hw-address",
            },
        ),
    ],
)

get_lease_by_hostname_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPLease,
            only="hostname",
        ),
    ],
)

add_reservation_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPReservation,
            only=[
                "ip_address",
                "hw_address",
                "hostname",
                "subnet_id",
                "operation_target",
            ],
            map=[
                ("ip_address", ("reservation", "ip-address")),
                ("hw_address", ("reservation", "hw-address")),
                (
                    "hostname",
                    ("reservation", "hostname"),
                ),
                ("subnet_id", ("reservation", "subnet-id")),
                ("operation_target", "operation-target"),
            ],
        ),
    ],
)

delete_reservation_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPReservation,
            only=[
                "subnet_id",
                "ip_address",
                "identifier_type",
                "identifier",
                "operation_target",
            ],
            map={
                "subnet_id": "subnet-id",
                "ip_address": "ip-address",
                "identifier_type": "identifier-type",
                "operation_target": "operation-target",
            },
        ),
    ],
)

get_all_reservations_retort = base_retort.extend(
    recipe=[
        name_mapping(
            DHCPSubnet,
            only="id",
            map=[
                ("id", ("subnet-id")),
            ],
        ),
    ],
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
        shared_network: list[DHCPSharedNetwork],
    ) -> None:
        """Add a new subnet."""
        data = add_subnet_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.SUBNET4_ADD,
                arguments=shared_network,
            ),
        )

        await self._make_request(data)

    async def update_subnet(
        self,
        subnet: DHCPSubnet,
    ) -> None:
        """Update an existing subnet."""
        data = update_subnet_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.SUBNET4_UPDATE,
                arguments=subnet,
            ),
        )

        await self._make_request(data)

    async def delete_subnet(
        self,
        subnet_id: int,
    ) -> None:
        """Delete a subnet."""
        data = delete_subnet_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.SUBNET4_DEL,
                arguments=DHCPSubnet(
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
                for item in response.json().get("arguments", [])
            ]
            if response is not None
            else []
        )

    async def get_subnet_by_id(self, subnet_id: int) -> DHCPSubnet:
        """Get a subnet by ID."""
        data = get_subnet_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.SUBNET4_GET,
                arguments=DHCPSubnet(id=subnet_id),
            ),
        )

        response = await self._make_request(
            data,
            return_response=True,
        )

        subnet_data = (
            response.json().get("arguments").get("subnets")[0]
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
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.LEASE4_ADD,
                arguments=lease,
            ),
        )

        await self._make_request(data)

    async def release_lease(self, ip_address: IPv4Address) -> None:
        """Release a lease by IP address."""
        data = release_lease_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.LEASE4_DEL,
                arguments=DHCPLease(ip_address=ip_address),
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
                arguments=[DHCPSubnet(id=_id) for _id in subnet_ids],
            ),
        )
        response = await self._make_request(
            data,
            return_response=True,
        )

        leases_data = (
            response.json().get("arguments").get("leases")
            if response
            else None
        )

        return (
            [
                DHCPLease(
                    id=item.get("id"),
                    ip_address=item.get("ip-address"),
                    mac_address=item.get("hw-address"),
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
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.LEASE4_GET_BY_HW_ADDRESS,
                arguments=DHCPLease(mac_address=hw_address),
            ),
        )

        response = await self._make_request(
            data,
            return_response=True,
        )

        lease_data = response.json().get("arguments") if response else {}

        return DHCPLease(
            id=lease_data.get("id"),
            ip_address=lease_data.get("ip-address"),
            mac_address=lease_data.get("hw-address"),
            hostname=lease_data.get("hostname"),
        )

    async def get_lease_by_hostname(self, ip_address: str) -> DHCPLease:
        """Get a lease by IP address."""
        data = get_lease_by_hostname_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.LEASE4_GET_BY_HOSTNAME,
                arguments=DHCPLease(ip_address=IPv4Address(ip_address)),
            ),
        )

        response = await self._make_request(
            data,
            return_response=True,
        )

        lease_data = response.json().get("arguments") if response else {}

        return DHCPLease(
            id=lease_data.get("id"),
            ip_address=lease_data.get("ip-address"),
            mac_address=lease_data.get("hw-address"),
            hostname=lease_data.get("hostname"),
        )

    async def create_reservation(
        self,
        reservation: DHCPReservation,
    ) -> None:
        """Create a new reservation."""
        data = add_reservation_retort.dump(
            KeaDHCPBaseAPIRequest(
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
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.RESERVATION_DEL,
                arguments=reservation,
            ),
        )

        await self._make_request(data)

    async def list_reservations(self, subnet_id: int) -> list[DHCPReservation]:
        """List all reservations."""
        data = list_subnet_retort.dump(
            KeaDHCPBaseAPIRequest(
                command=KeaDHCPCommands.RESERVATION_LIST,
                arguments=DHCPSubnet(id=subnet_id),
            ),
        )
        response = await self._make_request(
            data,
            return_response=True,
        )

        reservations_data = (
            (response.json().get("arguments").get("reservations"))
            if response
            else []
        )

        return [
            DHCPReservation(
                subnet_id=item.get("subnet-id"),
                ip_address=item.get("ip-address"),
                hw_address=item.get("hw-address"),
                hostname=item.get("hostname"),
                identifier=item.get("identifier"),
                identifier_type=item.get("identifier-type"),
                operation_target=item.get("operation-target"),
            )
            for item in reservations_data
        ]
