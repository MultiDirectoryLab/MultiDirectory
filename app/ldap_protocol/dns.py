"""DNS service for DNS records managing.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import functools
import re
import socket
from abc import ABC, abstractmethod
from enum import Enum, StrEnum
from typing import Any, Callable

import dns
import dns.asyncquery
import dns.update
from loguru import logger as loguru_logger
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from models import CatalogueSetting

DNS_MANAGER_STATE_NAME = "DNSManagerState"
DNS_MANAGER_ZONE_NAME = "DNSManagerZoneName"
DNS_MANAGER_IP_ADDRESS_NAME = "DNSManagerIpAddress"
DNS_MANAGER_TSIG_KEY_NAME = "DNSManagerTSIGKey"


log = loguru_logger.bind(name='DNSManager')

log.add(
    "logs/dnsmanager_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == 'dnsmanager',
    retention="10 days",
    rotation="1d",
    colorize=False)


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
            except DNSAPIError as err:
                logger.error(f'{name} call raised: {err}')
                raise

            else:
                if not is_stub:
                    logger.success(f"Executed {name}")
            return result

        return wrapped

    return wrapper


class DNSAPIError(Exception):
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


class DNSManagerState(StrEnum):
    """DNSManager state enum."""

    NOT_CONFIGURED = '0'
    SELFHOSTED = '1'
    HOSTED = '2'


class AbstractDNSManager(ABC):
    """Abstract DNS manager class."""

    def __init__(
        self,
        settings: DNSManagerSettings,
    ) -> None:
        """Set up DNS manager."""
        self._settings = settings

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
        if zone_file is not None:
            with open(settings.DNS_ZONE_FILE, "w") as f:
                f.write(zone_file)

            with open(settings.DNS_SERVER_NAMED_CONF_LOCAL, "a") as f:
                f.write(named_conf_local_part)

            with open(settings.DNS_SERVER_NAMED_CONF, "a") as f:
                f.write("\ninclude \"/opt/zone.key\";")

            with open(settings.DNS_TSIG_KEY, "r") as f:
                key_file_content = f.read()

            tsig_key = re.findall(r"\ssecret \"(\S+)\"", key_file_content)[0]

        session.add_all(
            [
                CatalogueSetting(
                    name=DNS_MANAGER_IP_ADDRESS_NAME,
                    value=dns_ip_address,
                ),
                CatalogueSetting(
                    name=DNS_MANAGER_ZONE_NAME,
                    value=domain,
                ),
                CatalogueSetting(
                    name=DNS_MANAGER_TSIG_KEY_NAME,
                    value=tsig_key,
                ),
            ],
        )

    @abstractmethod
    async def create_record( # noqa
        self, hostname: str, ip: str,
        record_type: str, ttl: int,
    ) -> None: ...

    @abstractmethod
    async def update_record( # noqa
        self, hostname: str, ip: str,
        record_type: str, ttl: int,
    ) -> None: ...

    @abstractmethod
    async def delete_record( # noqa
        self, hostname: str, ip: str,
        record_type: str,
    ) -> None: ...

    @abstractmethod
    async def get_all_records(self) -> list: ... # noqa


class DNSManager(AbstractDNSManager):
    """DNS server manager."""

    async def _send(self, action: dns.message.Message):
        """Send request to DNS server."""
        if self._settings.tsig_key is not None:
            action.use_tsig(
                keyring=dns.tsig.Key("zone.", self._settings.tsig_key),
                keyname="zone.",
            )

        await dns.asyncquery.tcp(action, where=self._settings.dns_server_ip)

    async def create_record(
        self, hostname: str, ip: str,
        record_type: str, ttl: int,
    ) -> None:
        """Create DNS record."""
        action = dns.update.Update(self._settings.zone_name)
        action.add(hostname, ttl, record_type, ip)

        await self._send(action)

    async def get_all_records(self) -> list:
        """Get all DNS records."""
        if self._settings.tsig_key is not None:
            loguru_logger.debug(self._settings.dns_server_ip)
            loguru_logger.debug(self._settings.domain)
            loguru_logger.debug(self._settings.tsig_key)
            zone_xfr_response = dns.query.xfr(
                self._settings.dns_server_ip,
                self._settings.domain,
                keyring={
                    dns.name.from_text("zone."):
                        dns.tsig.Key("zone.", self._settings.tsig_key)
                },
                keyalgorithm=dns.tsig.default_algorithm
            )
        else:
            zone_xfr_response = dns.query.xfr(
                self._settings.dns_server_ip, self._settings.domain,
            )

        zone = dns.zone.from_xfr(zone_xfr_response)

        result = {}
        for name, ttl, rdata in zone.iterate_rdatas():
            if rdata.rdtype.name in result.keys():
                result[rdata.rdtype.name].append({
                    "hostname":
                        name.to_text() + f".{self._settings.zone_name}",
                    "ip": rdata.to_text(),
                    "ttl": ttl,
                })
            else:
                if rdata.rdtype.name != "SOA":
                    result[rdata.rdtype.name] = [{
                        "hostname":
                            name.to_text() + f".{self._settings.zone_name}",
                        "ip": rdata.to_text(),
                        "ttl": ttl,
                    }]

        response = []
        for record_type in result:
            response.append({
                "record_type": record_type,
                "records": result[record_type],
            })

        return response

    async def update_record(
        self, hostname: str, ip: str,
        record_type: str, ttl: int,
    ):
        """Update DNS record."""
        action = dns.update.Update(self._settings.zone_name)
        action.replace(hostname, ttl, record_type, ip)

        await self._send(action)

    async def delete_record(
        self, hostname: str, ip: str,
        record_type: str,
    ) -> None:
        """Delete DNS record."""
        action = dns.update.Update(self._settings.zone_name)
        action.delete(hostname, record_type, ip)

        await self._send(action)


class StubDNSManager(AbstractDNSManager):
    """Stub client."""

    @logger_wraps(is_stub=True)
    async def create_record( # noqa
        self, hostname: str, ip: str,
        record_type: str, ttl: int,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def update_record( # noqa
        self, hostname: str, ip: str,
        record_type: str, ttl: int,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def delete_record( # noqa
        self, hostname: str, ip: str,
        record_type: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_all_records(self) -> list:
        return []


async def get_dns_state(
    session: AsyncSession,
) -> 'DNSManagerState':
    """Get or create DNS manager state."""
    state = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == DNS_MANAGER_STATE_NAME),
    )

    if state is None:
        session.add(
            CatalogueSetting(
                name=DNS_MANAGER_STATE_NAME,
                value=DNSManagerState.NOT_CONFIGURED,
            ),
        )
        await session.commit()
        return DNSManagerState.NOT_CONFIGURED

    return state.value


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


async def get_dns_manager_settings(
    session: AsyncSession,
) -> 'DNSManagerSettings':
    """Get DNS manager's settings."""
    settings_dict = {}
    for setting in await session.scalars(
        select(CatalogueSetting)
        .filter(or_(
            *[
                CatalogueSetting.name == DNS_MANAGER_ZONE_NAME,
                CatalogueSetting.name == DNS_MANAGER_IP_ADDRESS_NAME,
                CatalogueSetting.name == DNS_MANAGER_TSIG_KEY_NAME,
            ],
        )),
    ):
        settings_dict[setting.name] = setting.value

    dns_server_ip = settings_dict.get(DNS_MANAGER_IP_ADDRESS_NAME, None)

    if await get_dns_state(session) == DNSManagerState.SELFHOSTED:
        dns_server_ip = socket.gethostbyname("bind9")

    return DNSManagerSettings(
        zone_name=settings_dict.get(DNS_MANAGER_ZONE_NAME, None),
        dns_server_ip=dns_server_ip,
        tsig_key=settings_dict.get(DNS_MANAGER_TSIG_KEY_NAME, None),
    )


async def get_dns_manager_class(
    session: AsyncSession,
) -> type[AbstractDNSManager]:
    """Get DNS manager class."""
    if await get_dns_state(session) != DNSManagerState.NOT_CONFIGURED:
        return DNSManager
    return StubDNSManager
