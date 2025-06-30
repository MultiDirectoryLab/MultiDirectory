"""Utils for DNS server API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import functools
from typing import Any, Awaitable, Callable

from dns.asyncresolver import Resolver as AsyncResolver
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import CatalogueSetting

from .base import (
    DNS_MANAGER_IP_ADDRESS_NAME,
    DNS_MANAGER_STATE_NAME,
    DNS_MANAGER_TSIG_KEY_NAME,
    DNS_MANAGER_ZONE_NAME,
    DNSConnectionError,
    DNSManagerSettings,
    DNSManagerState,
    log,
)


def logger_wraps(is_stub: bool = False) -> Callable:
    """Log DNSManager calls.

    Returns:
        Callable: Decorator for logging DNSManager calls.
    """

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


async def get_dns_state(session: AsyncSession) -> "DNSManagerState":
    """Get or create DNS manager state.

    Args:
        session (AsyncSession): Database session.

    Returns:
        DNSManagerState: Current state of the DNS manager.
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
    """Update DNS state."""
    await session.execute(
        update(CatalogueSetting)
        .values({"value": state})
        .where(CatalogueSetting.name == DNS_MANAGER_STATE_NAME),
    )


async def resolve_dns_server_ip(host: str) -> str:
    """Get DNS server IP from Docker network.

    Returns:
        str: IP address of the DNS server.

    Raises:
        DNSConnectionError: If the DNS server IP cannot be resolved.
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
