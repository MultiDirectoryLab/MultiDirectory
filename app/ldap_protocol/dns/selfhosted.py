"""DNS service for SelfHosted DNS server managing.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import socket
from dataclasses import asdict
from ipaddress import IPv4Address, IPv6Address

from .base import (
    AbstractDNSManager,
    DNSForwarderServerStatus,
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSRecords,
    DNSRecordType,
    DNSServerParam,
    DNSZone,
    DNSZoneParam,
    DNSZoneType,
)
from .utils import logger_wraps


class SelfHostedDNSManager(AbstractDNSManager):
    """Manager for selfhosted Bind9 DNS server."""

    @logger_wraps()
    async def create_record(
        self,
        hostname: str,
        ip: str,
        record_type: DNSRecordType,
        ttl: int,
        zone_name: str | None = None,
    ) -> None:
        """Create DNS record."""
        await self._http_client.post(
            "/record",
            json={
                "zone_name": zone_name,
                "record_name": hostname,
                "record_type": record_type,
                "record_value": ip,
                "ttl": ttl,
            },
        )

    @logger_wraps()
    async def update_record(
        self,
        hostname: str,
        ip: str | None,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        await self._http_client.patch(
            "/record",
            json={
                "zone_name": zone_name,
                "record_name": hostname,
                "record_type": record_type,
                "record_value": ip,
                "ttl": ttl,
            },
        )

    @logger_wraps()
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        zone_name: str | None = None,
    ) -> None:
        await self._http_client.request(
            "delete",
            "/record",
            json={
                "zone_name": zone_name,
                "record_name": hostname,
                "record_type": record_type,
                "record_value": ip,
            },
        )

    @logger_wraps()
    async def get_all_records(self) -> list[DNSRecords]:
        response = await self._http_client.get("/zone")

        response_data = response.json()

        if (
            isinstance(response_data, list)
            and len(response_data) > 0
            and "records" in response_data[0]
        ):
            return response_data[0]["records"]
        else:
            return []

    @logger_wraps()
    async def get_all_zones_records(self) -> list[DNSZone]:
        response = await self._http_client.get("/zone")

        return response.json()

    @logger_wraps()
    async def get_forward_zones(self) -> list[DNSForwardZone]:
        response = await self._http_client.get("/zone/forward")

        return response.json()

    @logger_wraps()
    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        nameserver: str | None,
        params: list[DNSZoneParam],
    ) -> None:
        await self._http_client.post(
            "/zone",
            json={
                "zone_name": zone_name,
                "zone_type": zone_type,
                "nameserver": nameserver,
                "params": [asdict(param) for param in params],
            },
        )

    @logger_wraps()
    async def update_zone(
        self,
        zone_name: str,
        params: list[DNSZoneParam],
    ) -> None:
        await self._http_client.patch(
            "/zone",
            json={
                "zone_name": zone_name,
                "params": [asdict(param) for param in params],
            },
        )

    @logger_wraps()
    async def delete_zone(
        self,
        zone_names: list[str],
    ) -> None:
        for zone_name in zone_names:
            await self._http_client.request(
                "delete",
                "/zone",
                json={"zone_name": zone_name},
            )

    @logger_wraps()
    async def check_forward_dns_server(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
    ) -> DNSForwardServerStatus:
        str_dns_server_ip = str(dns_server_ip)
        try:
            hostname, _, _ = socket.gethostbyaddr(str_dns_server_ip)
            fqdn = socket.getfqdn(hostname)
        except socket.herror:
            return DNSForwardServerStatus(
                str_dns_server_ip,
                DNSForwarderServerStatus.NOT_FOUND,
                None,
            )
        return DNSForwardServerStatus(
            str_dns_server_ip,
            DNSForwarderServerStatus.VALIDATED,
            fqdn,
        )

    @logger_wraps()
    async def update_server_options(
        self,
        params: list[DNSServerParam],
    ) -> None:
        await self._http_client.patch(
            "/server/settings",
            json=[asdict(param) for param in params],
        )

    @logger_wraps()
    async def get_server_options(self) -> list[DNSServerParam]:
        response = await self._http_client.get("/server/settings")

        return response.json()

    @logger_wraps()
    async def restart_server(
        self,
    ) -> None:
        await self._http_client.get("/server/restart")

    @logger_wraps()
    async def reload_zone(
        self,
        zone_name: str,
    ) -> None:
        await self._http_client.get(f"/zone/{zone_name}")
