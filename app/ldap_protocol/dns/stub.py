"""Stub calls for DNS server API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .base import (
    AbstractDNSManager,
    DNSForwardZone,
    DNSRecords,
    DNSServerParam,
    DNSZoneParam,
    DNSZoneType,
)
from .utils import logger_wraps


class StubDNSManager(AbstractDNSManager):
    """Stub client."""

    @logger_wraps(is_stub=True)
    async def create_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        """Stub DNS manager create record."""

    @logger_wraps(is_stub=True)
    async def update_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int,
        zone_name: str | None = None,
    ) -> None:
        """Stub DNS manager update record."""

    @logger_wraps(is_stub=True)
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        zone_name: str | None = None,
    ) -> None:
        """Stub DNS manager delete record."""

    @logger_wraps(is_stub=True)
    async def get_all_zones_records(self) -> None:
        """Stub DNS manager get all zones records."""

    @logger_wraps(is_stub=True)
    async def get_forward_zones(self) -> list[DNSForwardZone]:
        """Stub DNS manager get forward zones.

        Returns:
            list[DNSForwardZone]: List of DNSForwardZone objects.
        """
        return []

    @logger_wraps(is_stub=True)
    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        nameserver: str | None,
        params: list[DNSZoneParam],
    ) -> None:
        """Stub DNS manager create zone."""

    @logger_wraps(is_stub=True)
    async def update_zone(
        self,
        zone_name: str,
        params: list[DNSZoneParam] | None,
    ) -> None:
        """Stub DNS manager update zone."""

    @logger_wraps(is_stub=True)
    async def delete_zone(self, zone_names: list[str]) -> None:
        """Stub DNS manager delete zone."""

    @logger_wraps(is_stub=True)
    async def check_forward_dns_server(self, dns_server_ip: str) -> None:
        """Stub DNS manager check forward DNS server."""

    @logger_wraps(is_stub=True)
    async def update_server_options(
        self,
        params: list[DNSServerParam],
    ) -> None:
        """Stub DNS manager update server options."""

    @logger_wraps(is_stub=True)
    async def get_server_options(self) -> list[DNSServerParam]:
        """Stub DNS manager get server options.

        Returns:
            list[DNSServerParam]: List of DNSServerParam objects.
        """
        return []

    @logger_wraps(is_stub=True)
    async def restart_server(self) -> None:
        """Stub DNS manager restart server."""

    @logger_wraps(is_stub=True)
    async def reload_zone(self, zone_name: str) -> None:
        """Stub DNS manager reload zone."""

    @logger_wraps(is_stub=True)
    async def get_all_records(self) -> list[DNSRecords]:
        """Stub DNS manager get all records.

        Returns:
            list[DNSRecords]: List of DNSRecords objects.
        """
        return []
