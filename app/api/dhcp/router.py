"""DHCP router.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Depends, status

from api.auth import verify_auth
from ldap_protocol.dhcp.schemas import (
    DHCPChangeStateSchemaRequest,
    DHCPLeaseSchemaRequest,
    DHCPLeaseSchemaResponse,
    DHCPReservationSchemaRequest,
    DHCPReservationSchemaResponse,
    DHCPStateSchemaResponse,
    DHCPSubnetSchemaAddRequest,
    DHCPSubnetSchemaResponse,
)

from .adapter import DHCPAdapter

dhcp_router = APIRouter(
    prefix="/dhcp",
    tags=["DHCP"],
    dependencies=[Depends(verify_auth)],
    route_class=DishkaRoute,
)


@dhcp_router.post("/service/change_state", status_code=status.HTTP_200_OK)
async def setup_dhcp(
    state_data: DHCPChangeStateSchemaRequest,
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> None:
    """Configure the DHCP server."""
    await dhcp_adapter.change_state(state_data)


@dhcp_router.get("/service/state")
async def get_dhcp_state(
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> DHCPStateSchemaResponse:
    """Get the current state of the DHCP server."""
    return await dhcp_adapter.get_state()


@dhcp_router.post("/subnet", status_code=status.HTTP_201_CREATED)
async def create_dhcp_subnet(
    subnet_data: DHCPSubnetSchemaAddRequest,
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> None:
    """Create a new subnet."""
    await dhcp_adapter.create_subnet(subnet_data)


@dhcp_router.get("/subnets")
async def get_dhcp_subnets(
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> list[DHCPSubnetSchemaResponse]:
    """Get all subnets."""
    return await dhcp_adapter.get_subnets()


@dhcp_router.put("/subnet/{subnet_id}")
async def update_dhcp_subnet(
    subnet_id: int,
    subnet_data: DHCPSubnetSchemaAddRequest,
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> None:
    """Update a subnet."""
    await dhcp_adapter.update_subnet(subnet_id, subnet_data)


@dhcp_router.delete("/subnet/{subnet_id}")
async def delete_dhcp_subnet(
    subnet_id: int,
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> None:
    """Delete a subnet."""
    await dhcp_adapter.delete_subnet(subnet_id)


@dhcp_router.post("/lease", status_code=status.HTTP_201_CREATED)
async def create_dhcp_lease(
    lease_data: DHCPLeaseSchemaRequest,
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> None:
    """Create a new lease."""
    await dhcp_adapter.create_lease(lease_data)


@dhcp_router.get("/lease/{subnet_id}")
async def get_dhcp_leases(
    subnet_id: int,
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> list[DHCPLeaseSchemaResponse]:
    """Get all leases."""
    return await dhcp_adapter.list_active_leases(subnet_id)


@dhcp_router.get("/lease/")
async def find_dhcp_lease(
    dhcp_adapter: FromDishka[DHCPAdapter],
    mac_address: str | None = None,
    hostname: str | None = None,
) -> DHCPLeaseSchemaResponse | None:
    """Find a lease by MAC address or hostname."""
    return await dhcp_adapter.find_lease(mac_address, hostname)


@dhcp_router.delete("/lease/{ip_address}")
async def delete_dhcp_lease(
    ip_address: IPv4Address,
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> None:
    """Delete a lease."""
    await dhcp_adapter.release_lease(ip_address)


@dhcp_router.post("/reservation", status_code=status.HTTP_201_CREATED)
async def create_dhcp_reservation(
    reservation_data: DHCPReservationSchemaRequest,
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> None:
    """Create a new reservation."""
    await dhcp_adapter.add_reservation(reservation_data)


@dhcp_router.get("/reservation/{subnet_id}")
async def get_dhcp_reservation(
    subnet_id: int,
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> list[DHCPReservationSchemaResponse]:
    """Get a reservation."""
    return await dhcp_adapter.get_reservations(subnet_id)


@dhcp_router.delete("/reservation")
async def delete_dhcp_reservation(
    mac_address: str,
    ip_address: IPv4Address,
    subnet_id: int,
    dhcp_adapter: FromDishka[DHCPAdapter],
) -> None:
    """Delete a reservation."""
    await dhcp_adapter.delete_reservation(
        mac_address,
        ip_address,
        subnet_id,
    )
