"""Stub calls for DNS server API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .base import AbstractDNSManager
from .dto import (
    DNSRRSetDTO,
    DNSZoneBaseDTO,
    DNSZoneForwardDTO,
    DNSZoneMasterDTO,
)
from .utils import logger_wraps


class StubDNSManager(AbstractDNSManager):
    """Stub client."""

    @logger_wraps(is_stub=True)
    async def create_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_records(
        self,
        zone_id: str,  # noqa: ARG002
    ) -> list[DNSRRSetDTO]:
        return []

    @logger_wraps(is_stub=True)
    async def get_zones(self) -> list[DNSZoneMasterDTO]: ...

    @logger_wraps(is_stub=True)
    async def get_forward_zones(self) -> list[DNSZoneForwardDTO]:
        return []

    @logger_wraps(is_stub=True)
    async def create_zone(
        self,
        zone: DNSZoneBaseDTO,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_zone(
        self,
        zone: DNSZoneBaseDTO,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_zone(
        self,
        zone_id: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def check_forward_dns_server(
        self,
        dns_server_ip: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_forward_zone(
        self,
        zone_id: str,
    ) -> None: ...
