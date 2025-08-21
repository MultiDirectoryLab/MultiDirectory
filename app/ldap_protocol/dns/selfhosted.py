"""DNS service for SelfHosted DNS server managing.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from dataclasses import asdict
from ipaddress import IPv4Address, IPv6Address

import dns.resolver

from .base import (
    AbstractDNSManager,
    DNSError,
    DNSForwarderServerStatus,
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSRecords,
    DNSRecordType,
    DNSServerParam,
    DNSZone,
    DNSZoneParam,
    DNSZoneType,
    log,
)
from .utils import logger_wraps

RESOLV_CONF_PATH = "/resolv.conf"


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
        response = await self._http_client.post(
            "/record",
            json={
                "zone_name": zone_name,
                "record_name": hostname,
                "record_type": record_type,
                "record_value": ip,
                "ttl": ttl,
            },
        )

        if response.status_code != 200:
            raise DNSError(response.text)

    @logger_wraps()
    async def update_record(
        self,
        hostname: str,
        ip: str | None,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        response = await self._http_client.patch(
            "/record",
            json={
                "zone_name": zone_name,
                "record_name": hostname,
                "record_type": record_type,
                "record_value": ip,
                "ttl": ttl,
            },
        )

        if response.status_code != 200:
            raise DNSError(response.text)

    @logger_wraps()
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        zone_name: str | None = None,
    ) -> None:
        response = await self._http_client.request(
            "delete",
            "/record",
            json={
                "zone_name": zone_name,
                "record_name": hostname,
                "record_type": record_type,
                "record_value": ip,
            },
        )

        if response.status_code != 200:
            raise DNSError(response.text)

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
        response = await self._http_client.post(
            "/zone",
            json={
                "zone_name": zone_name,
                "zone_type": zone_type,
                "nameserver": nameserver,
                "params": [asdict(param) for param in params],
            },
        )

        if response.status_code != 200:
            raise DNSError(response.text)

    @logger_wraps()
    async def update_zone(
        self,
        zone_name: str,
        params: list[DNSZoneParam],
    ) -> None:
        response = await self._http_client.patch(
            "/zone",
            json={
                "zone_name": zone_name,
                "params": [asdict(param) for param in params],
            },
        )

        if response.status_code != 200:
            raise DNSError(response.text)

    @logger_wraps()
    async def delete_zone(
        self,
        zone_names: list[str],
    ) -> None:
        for zone_name in zone_names:
            response = await self._http_client.request(
                "delete",
                "/zone",
                json={"zone_name": zone_name},
            )

            if response.status_code != 200:
                raise DNSError(response.text)

    def get_dns_servers(self) -> list[str]:
        """Get list of DNS servers."""
        dns_servers = []
        with open(RESOLV_CONF_PATH) as resolv_file:
            lines = resolv_file.readlines()

        for line in lines:
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) == 2:
                    dns_servers.append(parts[1].strip())

        return dns_servers

    @logger_wraps()
    async def find_forward_dns_fqdn(
        self,
        dns_servers: list[str],
        dns_server_ip: IPv4Address | IPv6Address,
    ) -> str | None:
        """Find forward DNS FQDN."""
        reversed_ip = (
            ".".join(reversed((str(dns_server_ip)).split(".")))
            + ".in-addr.arpa"
        )

        async def get_fqdn_and_latency(
            server: str,
        ) -> tuple[float, str | None]:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]

            try:
                event_loop = asyncio.get_running_loop()
                start_time = event_loop.time()
                fqdn = resolver.resolve(
                    reversed_ip,
                    "PTR",
                )
                latency = event_loop.time() - start_time

                return (latency, fqdn[0].to_text())
            except Exception:
                return (float("inf"), None)

        fqdn_list = await asyncio.gather(
            *(get_fqdn_and_latency(server) for server in dns_servers),
        )
        fqdn_list.sort(key=lambda x: x[0])
        return fqdn_list[0][1] if fqdn_list else None

    @logger_wraps()
    async def check_forward_dns_server(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
    ) -> DNSForwardServerStatus:
        str_dns_server_ip = str(dns_server_ip)
        dns_servers = self.get_dns_servers()
        log.info(f"{dns_servers}")

        if not dns_servers:
            raise ValueError("No DNS servers found in resolv.conf")

        try:
            fqdn = await self.find_forward_dns_fqdn(
                dns_servers,
                str_dns_server_ip,
            )
        except (dns.asyncresolver.NoAnswer, dns.asyncresolver.NXDOMAIN):
            return DNSForwardServerStatus(
                str_dns_server_ip,
                DNSForwarderServerStatus.NOT_VALIDATED,
                None,
            )

        if not fqdn:
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
        response = await self._http_client.patch(
            "/server/settings",
            json=[asdict(param) for param in params],
        )

        if response.status_code != 200:
            raise DNSError(response.text)

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
