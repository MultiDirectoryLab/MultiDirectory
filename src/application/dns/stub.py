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
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int,
        zone_name: str | None = None,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        zone_name: str | None = None,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_all_zones_records(self) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_forward_zones(self) -> list[DNSForwardZone]:
        return []

    @logger_wraps(is_stub=True)
    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        nameserver: str | None,
        params: list[DNSZoneParam],
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_zone(
        self,
        zone_name: str,
        params: list[DNSZoneParam] | None,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_zone(
        self,
        zone_names: list[str],
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def check_forward_dns_server(
        self,
        dns_server_ip: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_server_options(
        self,
        params: list[DNSServerParam],
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_server_options(self) -> list[DNSServerParam]:
        return []

    @logger_wraps(is_stub=True)
    async def restart_server(
        self,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def reload_zone(
        self,
        zone_name: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_all_records(self) -> list[DNSRecords]:
        """Stub DNS manager get all records."""
        return []
