"""DNS service for DNS records managing.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import functools
import socket
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Any, Awaitable, Callable

import httpx
from dns.asyncquery import inbound_xfr as make_inbound_xfr, tcp as asynctcp
from dns.asyncresolver import Resolver as AsyncResolver
from dns.message import Message, make_query as make_dns_query
from dns.name import from_text
from dns.rdataclass import IN
from dns.rdatatype import AXFR
from dns.tsig import Key as TsigKey
from dns.update import Update
from dns.zone import Zone
from loguru import logger as loguru_logger
from sqlalchemy import or_, select, update
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


def logger_wraps(is_stub: bool = False) -> Callable:
    """Log DNSManager calls."""

    def wrapper(func: Callable) -> Callable:
        name = func.__name__
        bus_type = " stub " if is_stub else " "

        @functools.wraps(func)
        async def wrapped(*args: str, **kwargs: str) -> Any:
            logger = log.opt(depth=1)

            logger.info(f"Calling{bus_type}'{name}'")
            try:
                result = await func(*args, **kwargs)
            except DNSConnectionError as err:
                logger.error(f"{name} call raised: {err}")
                raise

            else:
                if not is_stub:
                    logger.success(f"Executed {name}")
            return result

        return wrapped

    return wrapper


class DNSZoneType(str, Enum):
    """DNS zone types."""

    MASTER = "master"
    FORWARD = "forward"


class DNSForwarderServerStatus(str, Enum):
    """Forwarder DNS server statuses."""

    VALIDATED = "validated"
    NOT_VALIDATED = "not validated"
    NOT_FOUND = "not found"


class DNSConnectionError(ConnectionError):
    """API Error."""


class DNSRecordType(str, Enum):
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


class DNSZoneParamName(str, Enum):
    """Possible DNS zone option names."""

    acl = "acl"
    forwarders = "forwarders"
    ttl = "ttl"


class DNSServerParamName(str, Enum):
    """Possible DNS server option names."""

    dnssec = "dnssec-validation"


@dataclass
class DNSZoneParam:
    """DNS zone parameter."""

    name: DNSZoneParamName
    value: str | list[str]


@dataclass
class DNSServerParam:
    """DNS zone parameter."""

    name: DNSServerParamName
    value: str | list[str]


@dataclass
class DNSForwardServerStatus:
    """Forward DNS server status."""

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


class DNSManagerState(StrEnum):
    """DNSManager state enum."""

    NOT_CONFIGURED = "0"
    SELFHOSTED = "1"
    HOSTED = "2"


class AbstractDNSManager(ABC):
    """Abstract DNS manager class."""

    def __init__(self, settings: DNSManagerSettings) -> None:
        """Set up DNS manager."""
        self._dns_settings = settings

    @logger_wraps()
    async def setup(
        self,
        session: AsyncSession,
        dns_status: str,
        domain: str,
        dns_ip_address: str | None,
        tsig_key: str | None,
    ) -> None:
        """Set up DNS server and DNS manager."""
        if dns_status == DNSManagerState.SELFHOSTED:
            async with httpx.AsyncClient(
                timeout=30, base_url=f"http://{dns_ip_address}:8000"
            ) as client:
                await client.post(
                    "/setup",
                    json={
                        "zone_name": domain,
                        "dns_ip_address": dns_ip_address,
                    },
                )

            tsig_key = None

        new_settings = {
            DNS_MANAGER_IP_ADDRESS_NAME: dns_ip_address,
            DNS_MANAGER_ZONE_NAME: domain,
            DNS_MANAGER_TSIG_KEY_NAME: tsig_key,
        }
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
    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        acl: list[str] | None,
        params: list[DNSZoneParam],
    ) -> None: ...

    @abstractmethod
    async def update_zone(
        self,
        zone_name: str,
        acl: list[str] | None,
        params: list[DNSZoneParam] | None,
    ) -> None: ...

    @abstractmethod
    async def delete_zone(
        self,
        zone_name: str,
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
    async def restart_server(
        self,
    ) -> None: ...

    @abstractmethod
    async def reload_zone(
        self,
        zone_name: str,
    ) -> None: ...


class SelfHostedDNSManager(AbstractDNSManager):
    """Manager for selfhosted Bind9 DNS server."""

    _http_client: httpx.AsyncClient

    def __init__(self, settings: DNSManagerSettings) -> None:
        """Set settings and additionally set http client for DNS API."""
        super().__init__(settings=settings)
        self._http_client = httpx.AsyncClient(
            timeout=30, base_url=f"http://{settings.dns_server_ip}:8000"
        )

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
        async with self._http_client:
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
        async with self._http_client:
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
        async with self._http_client:
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
        response = None
        async with self._http_client:
            response = await self._http_client.get("/zone")

        return response.json()[0].get("records")

    @logger_wraps()
    async def get_all_zones_records(self) -> list[DNSZone]:
        response = None
        async with self._http_client:
            response = await self._http_client.get("/zone")

        return response.json()

    @logger_wraps()
    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        nameserver_ip: str,
        acl: list[str] | None,
        params: list[DNSZoneParam],
    ) -> None:
        async with self._http_client:
            await self._http_client.post(
                "/zone",
                json={
                    "zone_name": zone_name,
                    "zone_type": zone_type,
                    "nameserver_ip": nameserver_ip,
                    "acl": acl,
                    "params": params,
                },
            )

    @logger_wraps()
    async def update_zone(
        self,
        zone_name: str,
        params: list[DNSZoneParam] | None,
    ) -> None:
        async with self._http_client:
            await self._http_client.patch(
                "/zone",
                json={
                    "zone_name": zone_name,
                    "params": params,
                },
            )

    @logger_wraps()
    async def delete_zone(
        self,
        zone_name: str,
    ) -> None:
        async with self._http_client:
            await self._http_client.request(
                "delete",
                "/zone",
                json={"zone_name": zone_name},
            )

    @logger_wraps()
    async def check_forward_dns_server(
        self,
        dns_server_ip: str,
    ) -> DNSForwardServerStatus:
        try:
            hostname, _, _ = socket.gethostbyaddr(dns_server_ip)
            fqdn = socket.getfqdn(hostname)
        except socket.herror:
            return DNSForwardServerStatus(
                DNSForwarderServerStatus.NOT_FOUND,
                None,
            )
        return DNSForwardServerStatus(
            DNSForwarderServerStatus.VALIDATED,
            fqdn,
        )

    @logger_wraps()
    async def update_server_options(
        self,
        params: list[DNSServerParam],
    ) -> None:
        async with self._http_client:
            await self._http_client.patch(
                "/server/settings",
                json=params,
            )

    @logger_wraps()
    async def restart_server(
        self,
    ) -> None:
        async with self._http_client:
            await self._http_client.get("/server/restart")

    @logger_wraps()
    async def reload_zone(
        self,
        zone_name: str,
    ) -> None:
        async with self._http_client:
            await self._http_client.get(f"/zone/{zone_name}")


class DNSManager(AbstractDNSManager):
    """DNS server manager."""

    async def _send(self, action: Message) -> None:
        """Send request to DNS server."""
        if self._dns_settings.tsig_key is not None:
            action.use_tsig(
                keyring=TsigKey("zone.", self._dns_settings.tsig_key),
                keyname="zone.",
            )

        if self._dns_settings.dns_server_ip is None:
            raise DNSConnectionError

        await asynctcp(action, self._dns_settings.dns_server_ip)

    @logger_wraps()
    async def create_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        """Create DNS record."""
        action = Update(self._dns_settings.zone_name or zone_name)
        action.add(hostname, ttl, record_type, ip)

        await self._send(action)

    @logger_wraps()
    async def get_all_records(self) -> list[DNSRecords]:
        """Get all DNS records."""
        if (
            self._dns_settings.dns_server_ip is None
            or self._dns_settings.zone_name is None
        ):
            raise DNSConnectionError

        zone = from_text(self._dns_settings.zone_name)
        zone_tm = Zone(zone)
        query = make_dns_query(zone, AXFR, IN)

        if self._dns_settings.tsig_key is not None:
            query.use_tsig(
                keyring=TsigKey("zone.", self._dns_settings.tsig_key),
                keyname="zone.",
            )

        await make_inbound_xfr(
            self._dns_settings.dns_server_ip,
            zone_tm,
        )

        result: defaultdict[str, list] = defaultdict(list)
        for name, ttl, rdata in zone_tm.iterate_rdatas():
            record_type = rdata.rdtype.name

            if record_type == "SOA":
                continue

            result[record_type].append(
                DNSRecord(
                    record_name=(
                        name.to_text() + f".{self._dns_settings.zone_name}"
                    ),
                    record_value=rdata.to_text(),
                    ttl=ttl,
                )
            )

        return [
            DNSRecords(record_type=record_type, records=records)
            for record_type, records in result.items()
        ]

    @logger_wraps()
    async def update_record(
        self,
        hostname: str,
        ip: str | None,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        """Update DNS record."""
        action = Update(self._dns_settings.zone_name or zone_name)
        action.replace(hostname, ttl, record_type, ip)

        await self._send(action)

    @logger_wraps()
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        zone_name: str | None = None,
    ) -> None:
        """Delete DNS record."""
        action = Update(self._dns_settings.zone_name or zone_name)
        action.delete(hostname, record_type, ip)

        await self._send(action)

    @logger_wraps()
    async def get_all_zones_records(self) -> list[DNSZone]:
        raise NotImplementedError

    @logger_wraps()
    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        acl: list[str] | None,
        params: list[DNSZoneParam],
    ) -> None:
        raise NotImplementedError

    @logger_wraps()
    async def update_zone(
        self,
        zone_name: str,
        acl: list[str] | None,
        params: list[DNSZoneParam] | None,
    ) -> None:
        raise NotImplementedError

    @logger_wraps()
    async def delete_zone(
        self,
        zone_name: str,
    ) -> None:
        raise NotImplementedError

    @logger_wraps()
    async def check_forward_dns_server(
        self,
        dns_server_ip: str,
    ) -> DNSForwardServerStatus:
        raise NotImplementedError

    @logger_wraps()
    async def update_server_options(
        self,
        params: list[DNSServerParam],
    ) -> None:
        raise NotImplementedError

    @logger_wraps()
    async def restart_server(
        self,
    ) -> None:
        raise NotImplementedError

    @logger_wraps()
    async def reload_zone(
        self,
        zone_name: str,
    ) -> None:
        raise NotImplementedError


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
    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        acl: list[str] | None,
        params: list[DNSZoneParam],
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_zone(
        self,
        zone_name: str,
        acl: list[str] | None,
        params: list[DNSZoneParam] | None,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_zone(
        self,
        zone_name: str,
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


async def get_dns_state(
    session: AsyncSession,
) -> "DNSManagerState":
    """Get or create DNS manager state."""
    state = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == DNS_MANAGER_STATE_NAME)
    )  # fmt: skip

    if state is None:
        session.add(
            CatalogueSetting(
                name=DNS_MANAGER_STATE_NAME,
                value=DNSManagerState.NOT_CONFIGURED,
            ),
        )
        await session.commit()
        return DNSManagerState.NOT_CONFIGURED

    return DNSManagerState(state.value)


async def set_dns_manager_state(
    session: AsyncSession,
    state: DNSManagerState | str,
) -> None:
    """Update DNS state."""
    await session.execute(
        update(CatalogueSetting)
        .values({"value": state})
        .where(CatalogueSetting.name == DNS_MANAGER_STATE_NAME),
    )


async def resolve_dns_server_ip(host: str) -> str:
    """Get DNS server IP from Docker network."""
    async_resolver = AsyncResolver()
    dns_server_ip_resolve = await async_resolver.resolve(host)
    if dns_server_ip_resolve is None or dns_server_ip_resolve.rrset is None:
        raise DNSConnectionError
    return dns_server_ip_resolve.rrset[0].address


async def get_dns_manager_settings(
    session: AsyncSession,
    resolve_coro: Awaitable[str],
) -> "DNSManagerSettings":
    """Get DNS manager's settings."""
    settings_dict = {}
    for setting in await session.scalars(
        select(CatalogueSetting).filter(
            or_(
                CatalogueSetting.name == DNS_MANAGER_ZONE_NAME,
                CatalogueSetting.name == DNS_MANAGER_IP_ADDRESS_NAME,
                CatalogueSetting.name == DNS_MANAGER_TSIG_KEY_NAME,
            )
        )
    ):
        settings_dict[setting.name] = setting.value

    dns_server_ip = settings_dict.get(DNS_MANAGER_IP_ADDRESS_NAME)

    if await get_dns_state(session) == DNSManagerState.SELFHOSTED:
        dns_server_ip = await resolve_coro

    return DNSManagerSettings(
        zone_name=settings_dict.get(DNS_MANAGER_ZONE_NAME),
        dns_server_ip=dns_server_ip,
        tsig_key=settings_dict.get(DNS_MANAGER_TSIG_KEY_NAME),
    )


async def get_dns_manager_class(
    session: AsyncSession,
) -> type[AbstractDNSManager]:
    """Get DNS manager class."""
    dns_state = await get_dns_state(session)
    if dns_state == DNSManagerState.SELFHOSTED:
        return SelfHostedDNSManager
    elif dns_state == DNSManagerState.HOSTED:
        return DNSManager
    return StubDNSManager
