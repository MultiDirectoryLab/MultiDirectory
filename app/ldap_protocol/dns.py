"""DNS service for DNS records managing.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import functools
import re
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from typing import Awaitable, Callable

from dns.asyncquery import inbound_xfr as make_inbound_xfr, tcp as asynctcp
from dns.asyncresolver import Resolver as AsyncResolver
from dns.message import Message, make_query as make_dns_query
from dns.name import from_text
from dns.rdataclass import IN
from dns.rdatatype import AXFR
from dns.tsig import Key as TsigKey
from dns.update import Update
from dns.zone import Zone as DNSZone
from loguru import logger as loguru_logger
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
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
    """Log DNSManager calls.

    Args:
        is_stub (bool): If True, marks the logger as a stub. Default is False.

    Returns:
        Callable: Decorator for logging.
    """

    def wrapper(func: Callable) -> Callable:
        """Decorator for logging function calls.

        Args:
            func (Callable): Function to wrap.

        Returns:
            Callable: Wrapped function.
        """
        name = func.__name__
        bus_type = " stub " if is_stub else " "

        @functools.wraps(func)
        async def wrapped(*args: str, **kwargs: str) -> object:
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
        """Set settings.

        Args:
            zone_name (str | None): DNS zone name.
            dns_server_ip (str | None): DNS server IP address.
            tsig_key (str | None): TSIG key.
        """
        self.zone_name = zone_name
        self.domain = zone_name + "." if zone_name is not None else None
        self.dns_server_ip = dns_server_ip
        self.tsig_key = tsig_key


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
        settings: Settings,
        domain: str,
        dns_ip_address: str | None,
        zone_file: str | None,
        tsig_key: str | None,
        named_conf_local_part: str | None,
    ) -> None:
        """Set up DNS server and DNS manager."""
        if zone_file is not None and named_conf_local_part is not None:
            with open(settings.DNS_ZONE_FILE, "w") as f:
                f.write(zone_file)

            with open(settings.DNS_SERVER_NAMED_CONF_LOCAL, "a") as f:
                f.write(named_conf_local_part)

            with open(settings.DNS_SERVER_NAMED_CONF, "a") as f:
                f.write('\ninclude "/opt/zone.key";')

            with open(settings.DNS_TSIG_KEY) as f:
                key_file_content = f.read()

            tsig_key = re.findall(r"\ssecret \"(\S+)\"", key_file_content)[0]

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
    ) -> None: ...

    @abstractmethod
    async def update_record(
        self,
        hostname: str,
        ip: str | None,
        record_type: str,
        ttl: int | None,
    ) -> None: ...

    @abstractmethod
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
    ) -> None: ...

    @abstractmethod
    async def get_all_records(self) -> list[DNSRecords]: ...


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
    ) -> None:
        """Create DNS record."""
        action = Update(self._dns_settings.zone_name)
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
        zone_tm = DNSZone(zone)
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
    ) -> None:
        """Update DNS record."""
        action = Update(self._dns_settings.zone_name)
        action.replace(hostname, ttl, record_type, ip)

        await self._send(action)

    @logger_wraps()
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
    ) -> None:
        """Delete DNS record."""
        action = Update(self._dns_settings.zone_name)
        action.delete(hostname, record_type, ip)

        await self._send(action)


class StubDNSManager(AbstractDNSManager):
    """Stub client."""

    @logger_wraps(is_stub=True)
    async def create_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int | None,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_all_records(self) -> list[DNSRecords]:
        """Stub DNS manager get all records."""
        return []


async def get_dns_state(
    session: AsyncSession,
) -> "DNSManagerState":
    """Get or create DNS manager state.

    Args:
        session (AsyncSession): Database session.

    Returns:
        DNSManagerState: Current DNS manager state.
    """
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
    """Update DNS state.

    Args:
        session (AsyncSession): Database session.
        state (DNSManagerState | str): New DNS manager state.
    """
    await session.execute(
        update(CatalogueSetting)
        .values({"value": state})
        .where(CatalogueSetting.name == DNS_MANAGER_STATE_NAME),
    )


async def resolve_dns_server_ip(host: str) -> str:
    """Get DNS server IP from Docker network.

    Args:
        host (str): Hostname to resolve.

    Returns:
        str: Resolved IP address.

    Raises:
        DNSConnectionError: If DNS server IP cannot be resolved.
    """
    async_resolver = AsyncResolver()
    dns_server_ip_resolve = await async_resolver.resolve(host)
    if dns_server_ip_resolve is None or dns_server_ip_resolve.rrset is None:
        raise DNSConnectionError
    return dns_server_ip_resolve.rrset[0].address


async def get_dns_manager_settings(
    session: AsyncSession,
    resolve_coro: Awaitable[str],
) -> "DNSManagerSettings":
    """Get DNS manager's settings.

    Args:
        session (AsyncSession): Database session.
        resolve_coro (Awaitable[str]): Coroutine to resolve DNS server IP.

    Returns:
        DNSManagerSettings: DNS manager settings.
    """
    settings_dict = {}
    for setting in await session.scalars(
        select(CatalogueSetting).filter(
            or_(
                CatalogueSetting.name == DNS_MANAGER_ZONE_NAME,
                CatalogueSetting.name == DNS_MANAGER_IP_ADDRESS_NAME,
                CatalogueSetting.name == DNS_MANAGER_TSIG_KEY_NAME,
            )
        ),
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
    """Get DNS manager class.

    Args:
        session (AsyncSession): Database session.

    Returns:
        type[AbstractDNSManager]: DNS manager class type.
    """
    if await get_dns_state(session) != DNSManagerState.NOT_CONFIGURED:
        return DNSManager
    return StubDNSManager
