"""Abstract DNS service for DNS server managing.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

from loguru import logger as loguru_logger

from .dto import (
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
    DNSZoneBaseDTO,
)
from .enums import DNSForwarderServerStatus

DNS_MANAGER_STATE_NAME = "DNSManagerState"
DNS_MANAGER_ZONE_NAME = "DNSManagerZoneName"
DNS_MANAGER_IP_ADDRESS_NAME = "DNSManagerIpAddress"
DNS_MANAGER_TSIG_KEY_NAME = "DNSManagerTSIGKey"
log = loguru_logger.bind(name="DNSManager")

log.add(
    "logs/dnsmanager_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "dnsmanager",
    retention="10 days",
    rotation="1d",
    colorize=False,
)


class DNSZoneType(StrEnum):
    """DNS zone types."""

    MASTER = "master"
    FORWARD = "forward"


class DNSConnectionError(ConnectionError):
    """API Error."""


class DNSError(Exception):
    """DNS Error."""


class DNSNotImplementedError(NotImplementedError):
    """API Not Implemented Error."""


class DNSZoneParamName(StrEnum):
    """Possible DNS zone option names."""

    acl = "acl"
    forwarders = "forwarders"
    ttl = "ttl"


class DNSServerParamName(StrEnum):
    """Possible DNS server option names."""

    dnssec = "dnssec-validation"


@dataclass
class DNSZoneParam:
    """DNS zone parameter."""

    name: DNSZoneParamName
    value: str | list[str] | None


@dataclass
class DNSServerParam:
    """DNS zone parameter."""

    name: DNSServerParamName
    value: str | list[str]


@dataclass
class DNSForwardServerStatus:
    """Forward DNS server status."""

    ip: str
    status: DNSForwarderServerStatus
    FQDN: str | None


@dataclass
class DNSRecord:
    """Single dns record."""

    name: str
    value: str
    ttl: int


@dataclass
class DNSRecords:
    """Grouped dns records."""

    type: str
    records: list[DNSRecord]


@dataclass
class DNSZone:
    """DNS zone."""

    name: str
    type: DNSZoneType
    records: list[DNSRecords]


@dataclass
class DNSForwardZone:
    """DNS forward zone."""

    name: str
    type: DNSZoneType
    forwarders: list[str]


class DNSManagerSettings:
    """DNS Manager settings."""

    zone_name: str | None
    domain: str | None
    dns_server_ip: str | None
    tsig_key: str | None

    def __init__(
        self,
        zone_name: str | None,
        dns_server_ip: str | None,
        tsig_key: str | None,
    ) -> None:
        """Set settings."""
        self.zone_name = zone_name
        self.domain = zone_name + "." if zone_name is not None else None
        self.dns_server_ip = dns_server_ip
        self.tsig_key = tsig_key


class AbstractDNSManager:
    """Abstract DNS manager class."""

    _dns_settings: DNSManagerSettings

    def __init__(
        self,
        settings: DNSManagerSettings,
    ) -> None:
        """Set up DNS manager."""
        self._dns_settings = settings

    @abstractmethod
    async def setup(
        self,
        dns_server_settings: DNSSettingsDTO,
    ) -> None:
        """Set up DNS server and DNS manager."""
        raise DNSNotImplementedError

    @abstractmethod
    async def create_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None: ...

    @abstractmethod
    async def update_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None: ...

    @abstractmethod
    async def delete_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None: ...

    @abstractmethod
    async def get_records(
        self,
        zone_id: str,
    ) -> list[DNSRRSetDTO]: ...

    @abstractmethod
    async def get_zones(self) -> list[DNSMasterZoneDTO]: ...

    @abstractmethod
    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]:
        raise DNSNotImplementedError

    @abstractmethod
    async def create_zone(
        self,
        zone: DNSZoneBaseDTO,
    ) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def update_zone(
        self,
        zone: DNSZoneBaseDTO,
    ) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def delete_zone(
        self,
        zone_id: str,
    ) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def delete_forward_zone(
        self,
        zone_id: str,
    ) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def check_forward_dns_server(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
        host_dns_servers: list[str],
    ) -> DNSForwardServerStatus:
        raise DNSNotImplementedError
