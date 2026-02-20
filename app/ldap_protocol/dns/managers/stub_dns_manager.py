"""Stub calls for DNS server API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from ldap_protocol.dns.dto import (
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
)
from ldap_protocol.dns.managers.abstract_dns_manager import AbstractDNSManager
from ldap_protocol.dns.utils import logger_wraps


class StubDNSManager(AbstractDNSManager):
    """Stub client."""

    @logger_wraps(is_stub=True)
    async def setup(
        self,
        dns_settings: DNSSettingsDTO,
    ) -> None: ...

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
    async def get_master_zones(self) -> list[DNSMasterZoneDTO]:
        return []

    @logger_wraps(is_stub=True)
    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]:
        return []

    @logger_wraps(is_stub=True)
    async def create_master_zone(
        self,
        zone: DNSMasterZoneDTO,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def create_forward_zone(
        self,
        zone: DNSForwardZoneDTO,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_master_zone(
        self,
        zone: DNSMasterZoneDTO,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_forward_zone(
        self,
        zone: DNSForwardZoneDTO,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_master_zone(
        self,
        zone_id: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_forward_zone(
        self,
        zone_id: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def check_forward_dns_server(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
        host_dns_servers: list[str],
    ) -> None: ...
