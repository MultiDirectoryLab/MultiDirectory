"""Test DHCP adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv4Network
from unittest.mock import Mock

import pytest

from api.dhcp.adapter import DHCPAdapter
from ldap_protocol.dhcp.dataclasses import (
    DHCPLease,
    DHCPOptionData,
    DHCPPool,
    DHCPReservation,
    DHCPSubnet,
)
from ldap_protocol.dhcp.schemas import (
    DHCPLeaseSchemaRequest,
    DHCPReservationSchemaRequest,
    DHCPSubnetSchemaAddRequest,
)
from ldap_protocol.permissions_checker import AuthorizationProvider


@pytest.fixture
def dhcp_adapter(
    dhcp_manager: Mock,
    api_permissions_checker: AuthorizationProvider,
) -> DHCPAdapter:
    """Create DHCP adapter with mocked service."""
    adapter = DHCPAdapter(
        service=dhcp_manager,
        perm_checker=api_permissions_checker,
    )
    return adapter


@pytest.mark.asyncio
async def test_create_subnet_with_gateway(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test subnet creation with default gateway."""
    subnet_data = DHCPSubnetSchemaAddRequest(
        subnet=IPv4Network("192.168.1.0/24"),
        pool="192.168.1.100-192.168.1.200",
        default_gateway=IPv4Address("192.168.1.1"),
    )

    await dhcp_adapter.create_subnet(subnet_data)

    dhcp_manager.create_subnet.assert_called_once()
    call_args = dhcp_manager.create_subnet.call_args[0][0]

    assert call_args.subnet == IPv4Network("192.168.1.0/24")
    assert len(call_args.pools) == 1
    assert call_args.pools[0].pool == "192.168.1.100-192.168.1.200"
    assert len(call_args.option_data) == 1
    assert call_args.option_data[0].name == "routers"
    assert call_args.option_data[0].data == IPv4Address("192.168.1.1")


@pytest.mark.asyncio
async def test_create_subnet_without_gateway(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test subnet creation without default gateway."""
    subnet_data = DHCPSubnetSchemaAddRequest(
        subnet=IPv4Network("192.168.1.0/24"),
        pool="192.168.1.100-192.168.1.200",
        default_gateway=None,
    )

    await dhcp_adapter.create_subnet(subnet_data)

    dhcp_manager.create_subnet.assert_called_once()
    call_args = dhcp_manager.create_subnet.call_args[0][0]

    assert call_args.subnet == IPv4Network("192.168.1.0/24")
    assert len(call_args.pools) == 1
    assert call_args.pools[0].pool == "192.168.1.100-192.168.1.200"
    assert call_args.option_data == []


@pytest.mark.asyncio
async def test_delete_subnet(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test subnet deletion."""
    await dhcp_adapter.delete_subnet(1)

    dhcp_manager.delete_subnet.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_get_subnets(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test getting all subnets."""
    mock_subnets = [
        DHCPSubnet(
            id=1,
            subnet=IPv4Network("192.168.1.0/24"),
            pools=[
                DHCPPool(pool="192.168.1.100-192.168.1.200"),
            ],
            option_data=[
                DHCPOptionData(
                    name="routers",
                    data=IPv4Address("192.168.1.1"),
                ),
            ],
        ),
        DHCPSubnet(
            id=2,
            subnet=IPv4Network("192.168.2.0/24"),
            pools=[
                DHCPPool(pool="192.168.2.100-192.168.2.200"),
            ],
            option_data=None,
        ),
    ]
    dhcp_manager.get_subnets.return_value = mock_subnets

    result = await dhcp_adapter.get_subnets()

    assert len(result) == 2
    assert result[0].id == 1
    assert result[0].subnet == IPv4Network("192.168.1.0/24")
    assert result[0].default_gateway == IPv4Address("192.168.1.1")
    assert result[1].id == 2
    assert result[1].subnet == IPv4Network("192.168.2.0/24")
    assert result[1].default_gateway is None


@pytest.mark.asyncio
async def test_update_subnet(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test subnet update."""
    subnet_data = DHCPSubnetSchemaAddRequest(
        subnet=IPv4Network("192.168.1.0/24"),
        pool="192.168.1.50-192.168.1.150",
        default_gateway=IPv4Address("192.168.1.1"),
    )

    await dhcp_adapter.update_subnet(1, subnet_data)

    dhcp_manager.update_subnet.assert_called_once()
    call_args = dhcp_manager.update_subnet.call_args[0][0]

    assert call_args.id == 1
    assert call_args.subnet == IPv4Network("192.168.1.0/24")
    assert len(call_args.pools) == 1
    assert call_args.pools[0].pool == "192.168.1.50-192.168.1.150"


@pytest.mark.asyncio
async def test_create_lease(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test lease creation."""
    lease_data = DHCPLeaseSchemaRequest(
        subnet_id=1,
        ip_address=IPv4Address("192.168.1.100"),
        mac_address="00:11:22:33:44:55",
        hostname="workstation-01",
        valid_lifetime=3600,
    )

    await dhcp_adapter.create_lease(lease_data)

    dhcp_manager.create_lease.assert_called_once()
    call_args = dhcp_manager.create_lease.call_args[0][0]

    assert call_args.subnet_id == 1
    assert call_args.ip_address == IPv4Address("192.168.1.100")
    assert call_args.mac_address == "00:11:22:33:44:55"
    assert call_args.hostname == "workstation-01"


@pytest.mark.asyncio
async def test_release_lease(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test lease release."""
    await dhcp_adapter.release_lease(IPv4Address("192.168.1.100"))

    dhcp_manager.release_lease.assert_called_once_with(
        IPv4Address("192.168.1.100"),
    )


@pytest.mark.asyncio
async def test_list_active_leases(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test listing active leases."""
    mock_leases = [
        DHCPLease(
            subnet_id=1,
            ip_address=IPv4Address("192.168.1.100"),
            mac_address="00:11:22:33:44:55",
            hostname="workstation-01",
            cltt=1640995200,
            lifetime=3600,
        ),
        DHCPLease(
            subnet_id=1,
            ip_address=IPv4Address("192.168.1.101"),
            mac_address="00:11:22:33:44:56",
            hostname="workstation-02",
            cltt=1640995200,
            lifetime=3600,
        ),
    ]
    dhcp_manager.list_active_leases.return_value = mock_leases

    result = await dhcp_adapter.list_active_leases(1)

    assert len(result) == 2
    assert result[0].subnet_id == 1
    assert result[0].ip_address == IPv4Address("192.168.1.100")
    assert result[0].mac_address == "00:11:22:33:44:55"
    assert result[0].hostname == "workstation-01"
    assert result[0].expires is not None


@pytest.mark.asyncio
async def test_find_lease_found(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test finding lease when found."""
    mock_lease = DHCPLease(
        subnet_id=1,
        ip_address=IPv4Address("192.168.1.100"),
        mac_address="00:11:22:33:44:55",
        hostname="workstation-01",
        cltt=1640995200,
        lifetime=3600,
    )
    dhcp_manager.find_lease.return_value = mock_lease

    result = await dhcp_adapter.find_lease("00:11:22:33:44:55", None)

    assert result is not None
    assert result.subnet_id == 1
    assert result.ip_address == IPv4Address("192.168.1.100")
    assert result.mac_address == "00:11:22:33:44:55"
    assert result.hostname == "workstation-01"


@pytest.mark.asyncio
async def test_find_lease_not_found(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test finding lease when not found."""
    dhcp_manager.find_lease.return_value = None

    result = await dhcp_adapter.find_lease("00:00:00:00:00:00", None)

    assert result is None


@pytest.mark.asyncio
async def test_add_reservation(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test adding reservation."""
    reservation_data = DHCPReservationSchemaRequest(
        subnet_id=1,
        ip_address=IPv4Address("192.168.1.50"),
        mac_address="00:11:22:33:44:55",
        hostname="server-01",
    )

    await dhcp_adapter.add_reservation(reservation_data)

    dhcp_manager.add_reservation.assert_called_once()
    call_args = dhcp_manager.add_reservation.call_args[0][0]

    assert call_args.subnet_id == 1
    assert call_args.ip_address == IPv4Address("192.168.1.50")
    assert call_args.mac_address == "00:11:22:33:44:55"
    assert call_args.hostname == "server-01"


@pytest.mark.asyncio
async def test_delete_reservation(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test deleting reservation."""
    await dhcp_adapter.delete_reservation(
        "00:11:22:33:44:55",
        IPv4Address("192.168.1.50"),
        1,
    )

    dhcp_manager.delete_reservation.assert_called_once_with(
        "00:11:22:33:44:55",
        IPv4Address("192.168.1.50"),
        1,
    )


@pytest.mark.asyncio
async def test_get_reservations(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test getting reservations."""
    mock_reservations = [
        DHCPReservation(
            subnet_id=1,
            ip_address=IPv4Address("192.168.1.50"),
            mac_address="00:11:22:33:44:55",
            hostname="server-01",
        ),
        DHCPReservation(
            subnet_id=1,
            ip_address=IPv4Address("192.168.1.51"),
            mac_address="00:11:22:33:44:56",
            hostname="server-02",
        ),
    ]
    dhcp_manager.get_reservations.return_value = mock_reservations

    result = await dhcp_adapter.get_reservations(1)

    assert len(result) == 2
    assert result[0].subnet_id == 1
    assert result[0].ip_address == IPv4Address("192.168.1.50")
    assert result[0].mac_address == "00:11:22:33:44:55"
    assert result[0].hostname == "server-01"


@pytest.mark.asyncio
async def test_lease_to_reservation(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test lease to reservation transformation."""
    data = DHCPReservationSchemaRequest(
        subnet_id=1,
        ip_address=IPv4Address("192.168.1.50"),
        mac_address="00:11:22:33:44:55",
        hostname="server-01",
    )

    await dhcp_adapter.lease_to_reservation([data])

    dhcp_manager.lease_to_reservation.assert_called_once()
    call_args = dhcp_manager.lease_to_reservation.call_args[0][0][0]

    assert call_args.subnet_id == data.subnet_id
    assert call_args.ip_address == data.ip_address
    assert call_args.mac_address == data.mac_address
    assert call_args.hostname == data.hostname


@pytest.mark.asyncio
async def test_update_reservations(
    dhcp_adapter: DHCPAdapter,
    dhcp_manager: Mock,
) -> None:
    """Test updating reservation."""
    data = DHCPReservationSchemaRequest(
        subnet_id=1,
        ip_address=IPv4Address("192.168.1.50"),
        mac_address="00:11:22:33:44:55",
        hostname="server-01",
    )

    await dhcp_adapter.update_reservation(data)

    dhcp_manager.update_reservation.assert_called_once()
    call_args = dhcp_manager.update_reservation.call_args[0][0]

    assert call_args.subnet_id == data.subnet_id
    assert call_args.ip_address == data.ip_address
    assert call_args.mac_address == data.mac_address
    assert call_args.hostname == data.hostname
