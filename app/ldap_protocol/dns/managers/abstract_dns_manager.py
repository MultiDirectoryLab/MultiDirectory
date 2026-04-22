"""Abstract DNS manager for DNS server managing.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import abstractmethod
from ipaddress import IPv4Address, IPv6Address

from ldap_protocol.dns.clients.abstract_client import AbstractDNSForwardHTTPClient, AbstractDNSMasterHTTPClient
from ldap_protocol.dns.dto import (
    DNSForwardServerStatus,
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
)


class AbstractDNSManager:
    """Abstract DNS manager class."""

    _dns_settings: DNSSettingsDTO
    _dns_master_client: AbstractDNSMasterHTTPClient | None = None
    _dns_forward_client: AbstractDNSForwardHTTPClient | None = None

    def __init__(self, settings: DNSSettingsDTO) -> None:
        """Set up DNS manager."""
        self._dns_settings = settings

    @abstractmethod
    async def setup(self, dns_settings: DNSSettingsDTO, is_migration: bool = False) -> None: ...

    @abstractmethod
    async def create_record(self, zone_id: str, record: DNSRRSetDTO) -> None: ...

    @abstractmethod
    async def update_record(self, zone_id: str, record: DNSRRSetDTO) -> None: ...

    @abstractmethod
    async def delete_record(self, zone_id: str, record: DNSRRSetDTO) -> None: ...

    @abstractmethod
    async def get_records(self, zone_id: str) -> list[DNSRRSetDTO]: ...

    @abstractmethod
    async def get_master_zones(self) -> list[DNSMasterZoneDTO]: ...

    @abstractmethod
    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]: ...

    @abstractmethod
    async def create_master_zone(self, zone: DNSMasterZoneDTO, is_empty: bool = False) -> None: ...

    @abstractmethod
    async def create_forward_zone(self, zone: DNSForwardZoneDTO) -> None: ...

    @abstractmethod
    async def update_master_zone(self, zone: DNSMasterZoneDTO) -> None: ...

    @abstractmethod
    async def update_forward_zone(self, zone: DNSForwardZoneDTO) -> None: ...

    @abstractmethod
    async def delete_master_zone(self, zone_id: str) -> None: ...

    @abstractmethod
    async def delete_forward_zone(self, zone_id: str) -> None: ...

    @abstractmethod
    async def check_forward_dns_server(
        self, dns_server_ip: IPv4Address | IPv6Address, host_dns_servers: list[str]
    ) -> DNSForwardServerStatus: ...
