"""Utils for DNS server API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import functools
from typing import Any, Callable

from dns.asyncresolver import Resolver as AsyncResolver

from .base import log
from .dto import DNSRecordDTO, DNSRRSetDTO
from .enums import DNSRecordType, PowerDNSRecordChangeType
from .exceptions import DNSConnectionError


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


async def resolve_dns_server_ip(host: str) -> str:
    """Get DNS server IP from Docker network."""
    async_resolver = AsyncResolver()
    dns_server_ip_resolve = await async_resolver.resolve(host)
    if dns_server_ip_resolve is None or dns_server_ip_resolve.rrset is None:
        raise DNSConnectionError
    return dns_server_ip_resolve.rrset[0].address


async def get_new_zone_records(
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
