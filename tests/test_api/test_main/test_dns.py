"""Test DNS service."""

from dataclasses import asdict

import pytest
from httpx import AsyncClient
from starlette import status

from ldap_protocol.dns import (
    AbstractDNSManager,
    DNSManagerState,
    DNSServerParam,
    DNSServerParamName,
    DNSZoneParam,
    DNSZoneParamName,
)


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
        "/dns/record",
        json={
            "zone_name": zone_name,
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

    assert dns_manager.create_record.call_args.kwargs == {  # type: ignore
        "zone_name": "hello.zone"
    }

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
        "/dns/record",
        json={
            "zone_name": zone_name,
            "record_name": hostname,
            "record_value": ip,
            "record_type": record_type,
        },
    )

    dns_manager.delete_record.assert_called()  # type: ignore
    assert (
        dns_manager.delete_record.call_args.args  # type: ignore
    ) == (hostname, ip, record_type)

    assert dns_manager.delete_record.call_args.kwargs == {  # type: ignore
        "zone_name": "hello.zone"
    }

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
        "/dns/record",
        json={
            "zone_name": zone_name,
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

    assert dns_manager.update_record.call_args.kwargs == {  # type: ignore
        "zone_name": "hello.zone"
    }

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
        },
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
        "zone_name": "example.com",
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
    zone_type = "master"
    nameserver = None
    params = [
        DNSZoneParam(
            DNSZoneParamName.acl,
            ["127.0.0.1"],
        ),
    ]
    response = await http_client.post(
        "/dns/zone",
        json={
            "zone_name": zone_name,
            "zone_type": zone_type,
            "params": [asdict(param) for param in params],
        },
    )

    assert response.status_code == status.HTTP_200_OK
    dns_manager.create_zone.assert_called()  # type: ignore
    assert (
        dns_manager.create_zone.call_args.args  # type: ignore
    ) == (zone_name, zone_type, nameserver, params)


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_update_zone(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager update zone test."""
    zone_name = "hello"
    params = [
        DNSZoneParam(
            DNSZoneParamName.acl,
            ["127.0.0.1"],
        ),
    ]
    response = await http_client.patch(
        "/dns/zone",
        json={
            "zone_name": zone_name,
            "params": [asdict(param) for param in params],
        },
    )

    assert response.status_code == status.HTTP_200_OK
    dns_manager.update_zone.assert_called()  # type: ignore
    assert (
        dns_manager.update_zone.call_args.args  # type: ignore
    ) == (zone_name, params)


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_delete_zone(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager delete zone test."""
    zone_names = ["hello"]

    response = await http_client.request(
        "DELETE",
        "/dns/zone",
        json={"zone_names": zone_names},
    )

    assert response.status_code == status.HTTP_200_OK
    dns_manager.delete_zone.assert_called()  # type: ignore
    assert (
        dns_manager.delete_zone.call_args.args  # type: ignore
    ) == (zone_names,)


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_update_server_options(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager update DNS server options test."""
    params = [
        DNSServerParam(
            DNSServerParamName.dnssec,
            ["127.0.0.1"],
        ),
    ]
    response = await http_client.patch(
        "/dns/server/options",
        json=[asdict(param) for param in params],
    )

    assert response.status_code == status.HTTP_200_OK
    dns_manager.update_server_options.assert_called()  # type: ignore
    assert (
        dns_manager.update_server_options.call_args.args  # type: ignore
    ) == (params,)


@pytest.mark.asyncio
@pytest.mark.usefixtures("add_dns_settings")
@pytest.mark.usefixtures("session")
async def test_dns_get_server_options(
    http_client: AsyncClient,
    dns_manager: AbstractDNSManager,
) -> None:
    """DNS Manager get DNS server options test."""
    response = await http_client.get("/dns/server/options")

    assert response.status_code == status.HTTP_200_OK
    dns_manager.get_server_options.assert_called()  # type: ignore

    data = response.json()
    assert data == [
        {
            "name": "dnssec-validation",
            "value": "no",
        },
    ]


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
    dns_manager.get_all_zones_records.assert_called()  # type: ignore

    data = response.json()
    assert data == [
        {
            "zone_name": "test.local",
            "zone_type": "master",
            "records": [
                {
                    "record_type": "A",
                    "records": [
                        {
                            "record_name": "example.com",
                            "record_value": "127.0.0.1",
                            "ttl": 3600,
                        },
                    ],
                },
            ],
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
            "zone_name": "test.local",
            "zone_type": "forward",
            "forwarders": [
                "127.0.0.1",
                "127.0.0.2",
            ],
        },
    ]
