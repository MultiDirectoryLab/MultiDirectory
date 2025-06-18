"""Abstract DNS service for DNS server managing.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum

import httpx
from loguru import logger as loguru_logger
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from models import CatalogueSetting

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


class DNSForwarderServerStatus(StrEnum):
    """Forwarder DNS server statuses."""

    VALIDATED = "validated"
    NOT_VALIDATED = "not validated"
    NOT_FOUND = "not found"


class DNSConnectionError(ConnectionError):
    """API Error."""


class DNSRecordType(StrEnum):
    """DNS record types."""

    a = "A"
    aaaa = "AAAA"
    cname = "CNAME"
    mx = "MX"
    ns = "NS"
    txt = "TXT"
    soa = "SOA"
    ptr = "PTR"
    srv = "SRV"


class DNSZoneParamName(StrEnum):
    """Possible DNS zone option names."""

    acl = "acl"
    forwarders = "forwarders"
    ttl = "ttl"


class DNSServerParamName(StrEnum):
    """Possible DNS server option names."""

    dnssec = "dnssec-validation"


class DNSManagerState(StrEnum):
    """DNSManager state enum."""

    NOT_CONFIGURED = "0"
    SELFHOSTED = "1"
    HOSTED = "2"


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

    record_name: str
    record_value: str
    ttl: int


@dataclass
class DNSRecords:
    """Grouped dns records."""

    record_type: str
    records: list[DNSRecord]


@dataclass
class DNSZone:
    """DNS zone."""

    zone_name: str
    zone_type: DNSZoneType
    records: list[DNSRecords]


@dataclass
class DNSForwardZone:
    """DNS forward zone."""

    zone_name: str
    zone_type: DNSZoneType
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


class AbstractDNSManager(ABC):
    """Abstract DNS manager class."""

    _dns_settings: DNSManagerSettings
    _http_client: httpx.AsyncClient

    def __init__(
        self,
        settings: DNSManagerSettings,
        http_client: httpx.AsyncClient,
    ) -> None:
        """Set up DNS manager."""
        self._dns_settings = settings
        self._http_client = http_client

    async def setup(
        self,
        session: AsyncSession,
        dns_status: str,
        domain: str,
        dns_ip_address: str | None,
        tsig_key: str | None,
    ) -> None:
        """Set up DNS server and DNS manager."""
        if (
            dns_status == DNSManagerState.SELFHOSTED
            and self._http_client is not None
        ):
            await self._http_client.post(
                "/server/setup",
                json={"zone_name": domain},
            )

            tsig_key = None

        new_settings = {
            DNS_MANAGER_IP_ADDRESS_NAME: dns_ip_address,
            DNS_MANAGER_ZONE_NAME: domain,
        }
        if tsig_key is not None:
            new_settings[DNS_MANAGER_TSIG_KEY_NAME] = tsig_key

        if self._dns_settings.domain is not None:
            for name, value in new_settings.items():
                await session.execute(
                    update(CatalogueSetting)
                    .values({"value": value})
                    .where(CatalogueSetting.name == name),
                )
        else:
            session.add_all(
                [
                    CatalogueSetting(name=name, value=value)
                    for name, value in new_settings.items()
                ]
            )

    @abstractmethod
    async def create_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def update_record(
        self,
        hostname: str,
        ip: str | None,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        zone_name: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def get_all_records(self) -> list[DNSRecords]: ...

    @abstractmethod
    async def get_all_zones_records(self) -> list[DNSZone]: ...

    @abstractmethod
    async def get_forward_zones(self) -> list[DNSForwardZone]: ...

    @abstractmethod
    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        nameserver: str | None,
        params: list[DNSZoneParam],
    ) -> None: ...

    @abstractmethod
    async def update_zone(
        self,
        zone_name: str,
        params: list[DNSZoneParam] | None,
    ) -> None: ...

    @abstractmethod
    async def delete_zone(
        self,
        zone_names: list[str],
    ) -> None: ...

    @abstractmethod
    async def check_forward_dns_server(
        self,
        dns_server_ip: str,
    ) -> DNSForwardServerStatus: ...

    @abstractmethod
    async def update_server_options(
        self,
        params: list[DNSServerParam],
    ) -> None: ...

    @abstractmethod
    async def get_server_options(self) -> list[DNSServerParam]: ...

    @abstractmethod
    async def restart_server(
        self,
    ) -> None: ...

    @abstractmethod
    async def reload_zone(
        self,
        zone_name: str,
    ) -> None: ...
