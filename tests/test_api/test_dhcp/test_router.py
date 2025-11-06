"""Test DHCP API.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv4Network
from unittest.mock import Mock

import pytest
from fastapi import status
from httpx import AsyncClient

from ldap_protocol.dhcp.dataclasses import (
    DHCPLease,
    DHCPOptionData,
    DHCPPool,
    DHCPReservation,
    DHCPSubnet,
)
from ldap_protocol.dhcp.exceptions import (
    DHCPAPIError,
    DHCPEntryAddError,
    DHCPEntryNotFoundError,
)


@pytest.fixture
def sample_subnet_data() -> dict:
    """Sample subnet data for testing."""
    return {
        "subnet": "192.168.1.0/24",
        "pool": "192.168.1.100-192.168.1.200",
        "default_gateway": "192.168.1.1",
    }


@pytest.fixture
def sample_lease_data() -> dict:
    """Sample lease data for testing."""
    return {
        "subnet_id": 1,
        "ip_address": "192.168.1.100",
        "mac_address": "00:11:22:33:44:55",
        "hostname": "workstation-01",
        "valid_lifetime": 3600,
    }


@pytest.fixture
def sample_reservation_data() -> dict:
    """Sample reservation data for testing."""
    return {
        "subnet_id": 1,
        "ip_address": "192.168.1.50",
        "mac_address": "00:11:22:33:44:55",
        "hostname": "server-01",
    }


@pytest.fixture
def sample_subnet_response() -> DHCPSubnet:
    """Sample subnet response for testing."""
    return DHCPSubnet(
        id=1,
        subnet=IPv4Network("192.168.1.0/24"),
        pools=[DHCPPool(pool="192.168.1.100-192.168.1.200")],
        option_data=[
            DHCPOptionData(name="routers", data=IPv4Address("192.168.1.1")),
        ],
    )


@pytest.fixture
def sample_lease_response() -> DHCPLease:
    """Sample lease response for testing."""
    return DHCPLease(
        subnet_id=1,
        ip_address=IPv4Address("192.168.1.100"),
        mac_address="00:11:22:33:44:55",
        hostname="workstation-01",
        cltt=1640995200,
        lifetime=3600,
    )


@pytest.fixture
def sample_reservation_response() -> DHCPReservation:
    """Sample reservation response for testing."""
    return DHCPReservation(
        subnet_id=1,
        ip_address=IPv4Address("192.168.1.50"),
        mac_address="00:11:22:33:44:55",
        hostname="server-01",
    )


@pytest.mark.asyncio
async def test_create_subnet_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_subnet_data: dict,
) -> None:
    """Test successful subnet creation."""
    response = await http_client.post(
        "/dhcp/subnet",
        json=sample_subnet_data,
    )

    assert response.status_code == status.HTTP_201_CREATED
    dhcp_manager.create_subnet.assert_called_once()


@pytest.mark.asyncio
async def test_create_subnet_invalid_data(
    http_client: AsyncClient,
) -> None:
    """Test subnet creation with invalid data."""
    invalid_data = {
        "subnet": "invalid-subnet",
        "pool": "invalid-pool",
    }

    response = await http_client.post(
        "/dhcp/subnet",
        json=invalid_data,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_create_subnet_api_error(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_subnet_data: dict,
) -> None:
    """Test subnet creation with API error."""
    dhcp_manager.create_subnet.side_effect = DHCPEntryAddError(
        "Subnet already exists",
    )

    response = await http_client.post(
        "/dhcp/subnet",
        json=sample_subnet_data,
    )

    assert response.status_code == status.HTTP_409_CONFLICT
    assert "Subnet already exists" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_subnets_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_subnet_response: DHCPSubnet,
) -> None:
    """Test successful subnet retrieval."""
    dhcp_manager.get_subnets.return_value = [sample_subnet_response]

    response = await http_client.get("/dhcp/subnets")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == 1
    assert data[0]["subnet"] == "192.168.1.0/24"
    assert data[0]["default_gateway"] == "192.168.1.1"


@pytest.mark.asyncio
async def test_get_subnets_empty(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test getting subnets when none exist."""
    dhcp_manager.get_subnets.return_value = []

    response = await http_client.get("/dhcp/subnets")

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []


@pytest.mark.asyncio
async def test_update_subnet_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_subnet_data: dict,
) -> None:
    """Test successful subnet update."""
    response = await http_client.put(
        "/dhcp/subnet/1",
        json=sample_subnet_data,
    )

    assert response.status_code == status.HTTP_200_OK
    dhcp_manager.update_subnet.assert_called_once()


@pytest.mark.asyncio
async def test_update_subnet_not_found(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_subnet_data: dict,
) -> None:
    """Test subnet update when subnet not found."""
    dhcp_manager.update_subnet.side_effect = DHCPEntryNotFoundError(
        "Subnet not found",
    )

    response = await http_client.put(
        "/dhcp/subnet/999",
        json=sample_subnet_data,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_delete_subnet_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test successful subnet deletion."""
    response = await http_client.delete("/dhcp/subnet/1")

    assert response.status_code == status.HTTP_200_OK
    dhcp_manager.delete_subnet.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_delete_subnet_not_found(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test subnet deletion when subnet not found."""
    dhcp_manager.delete_subnet.side_effect = DHCPEntryNotFoundError(
        "Subnet not found",
    )

    response = await http_client.delete("/dhcp/subnet/999")

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_create_lease_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_lease_data: dict,
) -> None:
    """Test successful lease creation."""
    response = await http_client.post(
        "/dhcp/lease",
        json=sample_lease_data,
    )

    assert response.status_code == status.HTTP_201_CREATED
    dhcp_manager.create_lease.assert_called_once()


@pytest.mark.asyncio
async def test_create_lease_invalid_data(
    http_client: AsyncClient,
) -> None:
    """Test lease creation with invalid data."""
    invalid_data = {
        "subnet_id": "invalid",
        "ip_address": "invalid-ip",
        "mac_address": "invalid-mac",
    }

    response = await http_client.post(
        "/dhcp/lease",
        json=invalid_data,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_create_lease_api_error(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_lease_data: dict,
) -> None:
    """Test lease creation with API error."""
    dhcp_manager.create_lease.side_effect = DHCPEntryAddError(
        "IP already in use",
    )

    response = await http_client.post(
        "/dhcp/lease",
        json=sample_lease_data,
    )

    assert response.status_code == status.HTTP_409_CONFLICT
    assert "IP already in use" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_leases_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_lease_response: DHCPLease,
) -> None:
    """Test successful lease retrieval."""
    dhcp_manager.list_active_leases.return_value = [
        sample_lease_response,
    ]

    response = await http_client.get("/dhcp/lease/1")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 1
    assert data[0]["subnet_id"] == 1
    assert data[0]["ip_address"] == "192.168.1.100"
    assert data[0]["mac_address"] == "00:11:22:33:44:55"
    assert data[0]["hostname"] == "workstation-01"


@pytest.mark.asyncio
async def test_get_leases_empty(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test getting leases when none exist."""
    dhcp_manager.list_active_leases.return_value = []

    response = await http_client.get("/dhcp/lease/1")

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []


@pytest.mark.asyncio
async def test_find_lease_by_mac_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_lease_response: DHCPLease,
) -> None:
    """Test successful lease search by MAC address."""
    dhcp_manager.find_lease.return_value = sample_lease_response

    response = await http_client.get(
        "/dhcp/lease/?mac_address=00:11:22:33:44:55",
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["mac_address"] == "00:11:22:33:44:55"
    assert data["ip_address"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_find_lease_by_hostname_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_lease_response: DHCPLease,
) -> None:
    """Test successful lease search by hostname."""
    dhcp_manager.find_lease.return_value = sample_lease_response

    response = await http_client.get(
        "/dhcp/lease/?hostname=workstation-01",
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["hostname"] == "workstation-01"
    assert data["ip_address"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_find_lease_not_found(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test lease search when not found."""
    dhcp_manager.find_lease.return_value = None

    response = await http_client.get(
        "/dhcp/lease/?mac_address=00:00:00:00:00:00",
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() is None


@pytest.mark.asyncio
async def test_find_lease_no_params(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test lease search without parameters."""
    dhcp_manager.find_lease.side_effect = DHCPAPIError(
        "Either MAC address or hostname must be provided",
    )

    response = await http_client.get("/dhcp/lease/")

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_delete_lease_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test successful lease deletion."""
    response = await http_client.delete("/dhcp/lease/192.168.1.100")

    assert response.status_code == status.HTTP_200_OK
    dhcp_manager.release_lease.assert_called_once_with(
        IPv4Address("192.168.1.100"),
    )


@pytest.mark.asyncio
async def test_delete_lease_not_found(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test lease deletion when not found."""
    dhcp_manager.release_lease.side_effect = DHCPEntryNotFoundError(
        "Lease not found",
    )

    response = await http_client.delete("/dhcp/lease/192.168.1.128")

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_create_reservation_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_reservation_data: dict,
) -> None:
    """Test successful reservation creation."""
    response = await http_client.post(
        "/dhcp/reservation",
        json=sample_reservation_data,
    )

    assert response.status_code == status.HTTP_201_CREATED
    dhcp_manager.add_reservation.assert_called_once()


@pytest.mark.asyncio
async def test_create_reservation_invalid_data(
    http_client: AsyncClient,
) -> None:
    """Test reservation creation with invalid data."""
    invalid_data = {
        "subnet_id": "invalid",
        "ip_address": "invalid-ip",
        "mac_address": "invalid-mac",
    }

    response = await http_client.post(
        "/dhcp/reservation",
        json=invalid_data,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_create_reservation_api_error(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_reservation_data: dict,
) -> None:
    """Test reservation creation with API error."""
    dhcp_manager.add_reservation.side_effect = DHCPEntryAddError(
        "IP already reserved",
    )

    response = await http_client.post(
        "/dhcp/reservation",
        json=sample_reservation_data,
    )

    assert response.status_code == status.HTTP_409_CONFLICT
    assert "IP already reserved" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_reservations_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_reservation_response: DHCPReservation,
) -> None:
    """Test successful reservation retrieval."""
    dhcp_manager.get_reservations.return_value = [
        sample_reservation_response,
    ]

    response = await http_client.get("/dhcp/reservation/1")

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 1
    assert data[0]["subnet_id"] == 1
    assert data[0]["ip_address"] == "192.168.1.50"
    assert data[0]["mac_address"] == "00:11:22:33:44:55"
    assert data[0]["hostname"] == "server-01"


@pytest.mark.asyncio
async def test_get_reservations_empty(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test getting reservations when none exist."""
    dhcp_manager.get_reservations.return_value = []

    response = await http_client.get("/dhcp/reservation/1")

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []


@pytest.mark.asyncio
async def test_delete_reservation_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test successful reservation deletion."""
    response = await http_client.delete(
        "/dhcp/reservation",
        params={
            "mac_address": "00:11:22:33:44:55",
            "ip_address": "192.168.1.50",
            "subnet_id": 1,
        },
    )

    assert response.status_code == status.HTTP_200_OK
    dhcp_manager.delete_reservation.assert_called_once_with(
        "00:11:22:33:44:55",
        IPv4Address("192.168.1.50"),
        1,
    )


@pytest.mark.asyncio
async def test_delete_reservation_not_found(
    http_client: AsyncClient,
    dhcp_manager: Mock,
) -> None:
    """Test reservation deletion when not found."""
    dhcp_manager.delete_reservation.side_effect = DHCPEntryNotFoundError(
        "Reservation not found",
    )

    response = await http_client.delete(
        "/dhcp/reservation",
        params={
            "mac_address": "00:00:00:00:00:00",
            "ip_address": "192.168.1.128",
            "subnet_id": 999,
        },
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_delete_reservation_missing_params(
    http_client: AsyncClient,
) -> None:
    """Test reservation deletion with missing parameters."""
    response = await http_client.delete("/dhcp/reservation")

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
async def test_lease_to_reservation_success(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_reservation_data: dict,
) -> None:
    """Test successfull lease to reservation transformation."""
    response = await http_client.patch(
        "/dhcp/lease/to_reservation",
        json=sample_reservation_data,
    )

    assert response.status_code == status.HTTP_200_OK

    dhcp_manager.release_lease.assert_called_once()
    dhcp_manager.add_reservation.assert_called_once()


@pytest.mark.asyncio
async def test_lease_to_reservation_not_found(
    http_client: AsyncClient,
    dhcp_manager: Mock,
    sample_reservation_data: dict,
) -> None:
    """Test successfull lease to reservation transformation."""
    dhcp_manager.release_lease.side_effect = DHCPEntryNotFoundError(
        "Lease not found",
    )

    response = await http_client.patch(
        "/dhcp/lease/to_reservation",
        json=sample_reservation_data,
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND

    dhcp_manager.add_reservation.assert_not_called()
