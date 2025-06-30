"""Abstract DNS service for DNS server managing.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

import httpx
from loguru import logger as loguru_logger
from sqlalchemy import case, update
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


class DNSNotImplementedError(NotImplementedError):
    """API Not Implemented Error."""


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
        dns_ip_address: str | IPv4Address | IPv6Address | None,
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
            settings = [
                (CatalogueSetting.name == name, value)
                for name, value in new_settings.items()
            ]

            await session.execute(
                update(CatalogueSetting)
                .where(CatalogueSetting.name.in_(new_settings.keys()))
                .values({
                    "value": case(
                        *settings,
                        else_=CatalogueSetting.value,
                    )
                })
            )
        else:
            session.add_all([
                CatalogueSetting(name=name, value=value)
                for name, value in new_settings.items()
            ])

    @abstractmethod
    async def create_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        """Create DNS record."""

    @abstractmethod
    async def update_record(
        self,
        hostname: str,
        ip: str | None,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        """Update DNS record."""

    @abstractmethod
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        zone_name: str | None = None,
    ) -> None:
        """Delete DNS record."""

    @abstractmethod
    async def get_all_records(self) -> list[DNSRecords]:
        """Get all DNS records of all zones.

        Raises:
            DNSNotImplementedError: If the method is not implemented.

        Returns:
            list[DNSRecords]: List of DNSRecords objects with records.
        """
        raise DNSNotImplementedError

    @abstractmethod
    async def get_all_zones_records(self) -> list[DNSZone]:
        """Get all DNS records grouped by zone.

        Raises:
            DNSNotImplementedError: If the method is not implemented.

        Returns:
            list[DNSZone]: List of DNSZone objects with records.
        """
        raise DNSNotImplementedError

    @abstractmethod
    async def get_forward_zones(self) -> list[DNSForwardZone]:
        """Get all forward zones.

        Raises:
            DNSNotImplementedError: If the method is not implemented.

        Returns:
            list[DNSForwardZone]: List of DNSForwardZone objects.
        """
        raise DNSNotImplementedError

    @abstractmethod
    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        nameserver: str | None,
        params: list[DNSZoneParam],
    ) -> None:
        """Create DNS zone.

        Args:
            zone_name (str): Name of the zone.
            zone_type (DNSZoneType): Type of the zone (master or forward).
            nameserver (str | None): Nameserver for the zone, if applicable.
            params (list[DNSZoneParam]): List of parameters for the zone.

        Raises:
            DNSNotImplementedError: If the method is not implemented.
        """
        raise DNSNotImplementedError

    @abstractmethod
    async def update_zone(
        self,
        zone_name: str,
        params: list[DNSZoneParam] | None,
    ) -> None:
        """Update DNS zone.

        Args:
            zone_name (str): Name of the zone to update.
            params (list[DNSZoneParam] | None): List of parameters to update.

        Raises:
            DNSNotImplementedError: If the method is not implemented.
        """
        raise DNSNotImplementedError

    @abstractmethod
    async def delete_zone(self, zone_names: list[str]) -> None:
        """Delete DNS zone.

        Args:
            zone_names (list[str]): List of zone names to delete.

        Raises:
            DNSNotImplementedError: If the method is not implemented.
        """
        raise DNSNotImplementedError

    @abstractmethod
    async def check_forward_dns_server(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
    ) -> DNSForwardServerStatus:
        """Check if the given DNS server is reachable and valid.

        Args:
            dns_server_ip (IPv4Address | IPv6Address): IP address of DNS server

        Returns:
            DNSForwardServerStatus: Status of the DNS server.

        Raises:
            DNSNotImplementedError: If the method is not implemented.
        """
        raise DNSNotImplementedError

    @abstractmethod
    async def update_server_options(
        self,
        params: list[DNSServerParam],
    ) -> None:
        """Update DNS server options.

        Args:
            params (list[DNSServerParam]): List of server parameters to update.

        Raises:
            DNSNotImplementedError: If the method is not implemented.
        """
        raise DNSNotImplementedError

    @abstractmethod
    async def get_server_options(self) -> list[DNSServerParam]:
        """Get list of modifiable DNS server params.

        Raises:
            DNSNotImplementedError: If the method is not implemented.

        Returns:
            list[DNSServerParam]: List of DNSServerParam objects.
        """
        raise DNSNotImplementedError

    @abstractmethod
    async def restart_server(self) -> None:
        """Restart DNS server.

        Raises:
            DNSNotImplementedError: If the method is not implemented.
        """
        raise DNSNotImplementedError

    @abstractmethod
    async def reload_zone(self, zone_name: str) -> None:
        """Reload DNS zone.

        Args:
            zone_name (str): Name of the zone to reload.

        Raises:
            DNSNotImplementedError: If the method is not implemented.
        """
        raise DNSNotImplementedError
