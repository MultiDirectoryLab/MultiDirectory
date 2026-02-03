"""Utils for DNS server API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import functools
from typing import Any, Callable

from dns.asyncresolver import Resolver as AsyncResolver
from loguru import logger

from ldap_protocol.dns.dto import DNSRecordDTO, DNSRRSetDTO
from ldap_protocol.dns.enums import DNSRecordType, PowerDNSRecordChangeType
from ldap_protocol.dns.exceptions import DNSConnectionError, DNSError

log = logger.bind(name="DNSManager")

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
            except DNSError as err:
                logger.error(f"{name} call raised: {err}")
                raise

            return result

        return wrapped

    return wrapper


async def resolve_dns_server_ip(host: str) -> str:
    """Get DNS server IP from Docker network."""
    async_resolver = AsyncResolver()
    dns_server_ip_resolve = await async_resolver.resolve(host)
    if dns_server_ip_resolve is None or dns_server_ip_resolve.rrset is None:
        raise DNSConnectionError
    return dns_server_ip_resolve.rrset[0].address


async def create_initial_zone_records(
    domain: str,
    nameserver: str,
) -> list[DNSRRSetDTO]:
    """Get initial records for new zone."""
    return [
        DNSRRSetDTO(
            name=f"{domain}",
            type=DNSRecordType.A,
            records=[
                DNSRecordDTO(
                    content=nameserver,
                    disabled=False,
                    modified_at=None,
                ),
            ],
            changetype=PowerDNSRecordChangeType.EXTEND,
            ttl=3600,
        ),
        DNSRRSetDTO(
            name=f"ns1.{domain}",
            type=DNSRecordType.A,
            records=[
                DNSRecordDTO(
                    content=nameserver,
                    disabled=False,
                    modified_at=None,
                ),
            ],
            changetype=PowerDNSRecordChangeType.EXTEND,
            ttl=3600,
        ),
        DNSRRSetDTO(
            name=f"{domain}",
            type=DNSRecordType.SOA,
            records=[
                DNSRecordDTO(
                    content=f"ns1.{domain} hostmaster.{domain}"
                    + " 1 10800 3600 604800 3600",
                    disabled=False,
                    modified_at=None,
                ),
            ],
            changetype=PowerDNSRecordChangeType.EXTEND,
            ttl=3600,
        ),
    ]
