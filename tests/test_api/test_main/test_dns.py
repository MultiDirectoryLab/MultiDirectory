"""Test DNS service."""

import pytest
from httpx import AsyncClient
from starlette import status

from ldap_protocol.dns import AbstractDNSManager
from ldap_protocol.dns.dto import DNSRecordDTO, DNSRRSetDTO, DNSZoneMasterDTO


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_dns_create_record(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager create record test."""
    zone_name = "hello.zone"
    hostname = "hello"
    ip = "127.0.0.1"
    record_type = "A"
    ttl = 3600
    response = await http_client.post(
        f"/dns/record/{zone_name}",
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
    ) == (
        zone_name,
        DNSRRSetDTO(
            name=hostname,
            type=record_type,
            records=[
                DNSRecordDTO(
                    content=ip,
                    disabled=False,
                ),
            ],
            ttl=ttl,
        ),
    )

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_dns_delete_record(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager delete record test."""
    zone_name = "hello.zone"
    hostname = "hello"
    ip = "127.0.0.1"
    record_type = "A"
    response = await http_client.request(
        "DELETE",
        f"/dns/record/{zone_name}",
        json={
            "record_name": hostname,
            "record_value": ip,
            "record_type": record_type,
        },
    )

    dns_manager.delete_record.assert_called()  # type: ignore
    assert (
        dns_manager.delete_record.call_args.args  # type: ignore
    ) == (
        zone_name,
        DNSRRSetDTO(
            name=hostname,
            type=record_type,
            records=[
                DNSRecordDTO(
                    content=ip,
                    disabled=False,
                ),
            ],
        ),
    )

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_dns_update_record(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager update record test."""
    zone_name = "hello.zone"
    hostname = "hello"
    ip = "127.0.0.1"
    record_type = "A"
    ttl = 3600
    response = await http_client.request(
        "PATCH",
        f"/dns/record/{zone_name}",
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
    ) == (
        zone_name,
        DNSRRSetDTO(
            name=hostname,
            type=record_type,
            records=[
                DNSRecordDTO(
                    content=ip,
                    disabled=False,
                ),
            ],
            ttl=ttl,
        ),
    )

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_dns_get_all_records(http_client: AsyncClient) -> None:
    """DNS Manager get all records test."""
    zone_name = "hello.zone"
    response = await http_client.get(f"/dns/record/{zone_name}")

    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data == [
        {
            "name": "example.com",
            "type": "A",
            "changetype": None,
            "records": [
                {
                    "content": "127.0.0.1",
                    "disabled": False,
                    "modified_at": None,
                },
            ],
            "ttl": 3600,
        },
    ]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_dns_setup_selfhosted(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager setup test."""
    domain = "example.com"
    tsig_key = None
    dns_ip_address = "127.0.0.1"
    response = await http_client.post(
        "/dns/setup",
        json={
            "domain": domain,
            "dns_ip_address": dns_ip_address,
            "tsig_key": tsig_key,
        },
    )

    assert response.status_code == status.HTTP_200_OK

    dns_manager.setup.assert_called()  # type: ignore


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_get_status(http_client: AsyncClient) -> None:
    """DNS Manager get status test."""
    response = await http_client.get("/dns/status")

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "dns_status": "2",
        "zone_name": "example.com.",
        "dns_server_ip": "127.0.0.1",
    }


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_create_zone(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager create zone test."""
    zone_name = "hello"
    nameserver = "192.168.1.1"
    response = await http_client.post(
        "/dns/zone",
        json={
            "zone_name": zone_name,
            "nameserver_ip": nameserver,
            "dnssec": False,
        },
    )

    assert response.status_code == status.HTTP_200_OK
    dns_manager.create_zone.assert_called()  # type: ignore
    assert (
        dns_manager.create_zone.call_args.args  # type: ignore
    ) == (
        DNSZoneMasterDTO(
            id=zone_name,
            rrsets=[],
            name=zone_name,
            dnssec=False,
            type="zone",
            nameservers=[],
            kind="Master",
        ),
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_update_zone(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager update zone test."""
    zone_name = "hello"
    nameserver = "192.168.1.1"
    response = await http_client.patch(
        "/dns/zone",
        json={
            "zone_name": zone_name,
            "nameserver_ip": nameserver,
            "dnssec": False,
        },
    )

    assert response.status_code == status.HTTP_200_OK
    dns_manager.update_zone.assert_called()  # type: ignore
    assert (
        dns_manager.update_zone.call_args.args  # type: ignore
    ) == (
        DNSZoneMasterDTO(
            id=zone_name,
            rrsets=[],
            name=zone_name,
            dnssec=False,
            type="zone",
            nameservers=[],
            kind="Master",
        ),
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_delete_zone(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager delete zone test."""
    zone_ids = ["hello"]

    response = await http_client.request(
        "DELETE",
        "/dns/zone",
        json={"zone_ids": zone_ids},
    )

    assert response.status_code == status.HTTP_200_OK
    dns_manager.delete_zone.assert_called()  # type: ignore
    assert (
        dns_manager.delete_zone.call_args.args  # type: ignore
    ) == (zone_ids[0],)


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_get_all_zones_with_records(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager get DNS server settings test."""
    response = await http_client.get("/dns/zone")

    assert response.status_code == status.HTTP_200_OK
    dns_manager.get_zones.assert_called()  # type: ignore

    data = response.json()
    assert data == [
        {
            "id": "zone1",
            "name": "example.com.",
            "rrsets": [
                {
                    "name": "example.com",
                    "type": "A",
                    "changetype": None,
                    "records": [
                        {
                            "content": "127.0.0.1",
                            "disabled": False,
                            "modified_at": None,
                        },
                    ],
                    "ttl": 3600,
                },
            ],
            "dnssec": False,
            "nameservers": ["ns1.example.com."],
            "kind": "Master",
            "type": "zone",
        },
    ]


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_get_all_forward_zones(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager get DNS server settings test."""
    response = await http_client.get("/dns/zone/forward")

    assert response.status_code == status.HTTP_200_OK
    dns_manager.get_forward_zones.assert_called()  # type: ignore

    data = response.json()
    assert data == [
        {
            "id": "forward1",
            "name": "forward1.",
            "rrsets": [],
            "kind": "Forwarded",
            "type": "zone",
            "servers": ["127.0.0.1"],
            "recursion_desired": False,
        },
    ]
