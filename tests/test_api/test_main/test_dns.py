"""Test DNS service."""

import pytest
from httpx import AsyncClient
from starlette import status

from ldap_protocol.dns import AbstractDNSManager, DNSManagerState


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_dns_create_record(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager create record test."""
    hostname = "hello"
    ip = "127.0.0.1"
    record_type = "A"
    ttl = 3600
    response = await http_client.post(
        "/dns/record",
        json={
            "record_name": hostname,
            "record_value": ip,
            "record_type": record_type,
            "ttl": ttl,
        },
    )

    dns_manager.create_record.assert_called()  # type: ignore
    assert (
        dns_manager.create_record.call_args.args  # type: ignore
    ) == (hostname, ip, record_type, int(ttl))

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_dns_delete_record(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager delete record test."""
    hostname = "hello"
    ip = "127.0.0.1"
    record_type = "A"
    response = await http_client.request(
        "DELETE",
        "/dns/record",
        json={
            "record_name": hostname,
            "record_value": ip,
            "record_type": record_type,
        },
    )

    dns_manager.delete_record.assert_called()  # type: ignore
    assert (
        dns_manager.delete_record.call_args.args  # type: ignore
    ) == (hostname, ip, record_type)

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_dns_update_record(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager update record test."""
    hostname = "hello"
    ip = "127.0.0.1"
    record_type = "A"
    ttl = 3600
    response = await http_client.request(
        "PATCH",
        "/dns/record",
        json={
            "record_name": hostname,
            "record_value": ip,
            "record_type": record_type,
            "ttl": ttl,
        },
    )

    dns_manager.update_record.assert_called()  # type: ignore
    assert (
        dns_manager.update_record.call_args.args  # type: ignore
    ) == (hostname, ip, record_type, int(ttl))

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_dns_get_all_records(http_client: AsyncClient) -> None:
    """DNS Manager get all records test."""
    response = await http_client.get("/dns/record")

    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data == [
        {
            "record_type": "A",
            "records": [
                {
                    "record_name": "example.com",
                    "record_value": "127.0.0.1",
                    "ttl": 3600,
                }
            ],
        }
    ]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_dns_setup_selfhosted(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager setup test."""
    dns_status = DNSManagerState.SELFHOSTED
    domain = "example.com"
    tsig_key = None
    dns_ip_address = None
    response = await http_client.post(
        "/dns/setup",
        json={
            "dns_status": dns_status,
            "domain": domain,
            "dns_ip_address": dns_ip_address,
            "tsig_key": tsig_key,
        },
    )

    assert response.status_code == status.HTTP_200_OK

    dns_manager.setup.assert_called()


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_get_status(http_client: AsyncClient) -> None:
    """DNS Manager get status test."""
    response = await http_client.get("/dns/status")

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "dns_status": "2",
        "zone_name": "example.com",
        "dns_server_ip": "127.0.0.1",
    }
