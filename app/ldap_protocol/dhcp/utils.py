"""Utils for DHCP server API.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import functools
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import CatalogueSetting

from .base import DHCP_MANAGER_STATE_NAME, DHCPManagerState, log
from .exceptions import DHCPConnectionError


def logger_wraps(is_stub: bool = False) -> Callable:
    """Log DHCPManager calls."""

    def wrapper(func: Callable) -> Callable:
        name = func.__name__
        bus_type = " stub " if is_stub else " "

        @functools.wraps(func)
        async def wrapped(*args: str, **kwargs: str) -> Any:
            logger = log.opt(depth=1)

            logger.info(f"Calling{bus_type}'{name}'")
            try:
                result = await func(*args, **kwargs)
            except DHCPConnectionError as err:
                logger.error(f"{name} call raised: {err}")
                raise

            else:
                if not is_stub:
                    logger.success(f"Executed {name}")
            return result

        return wrapped

    return wrapper


async def get_dhcp_state(
    session: AsyncSession,
) -> "DHCPManagerState":
    """Get or create DHCP manager state."""
    state = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == DHCP_MANAGER_STATE_NAME),
    )  # fmt: skip

    if state is None:
        session.add(
            CatalogueSetting(
                name=DHCP_MANAGER_STATE_NAME,
                value=DHCPManagerState.NOT_CONFIGURED,
            ),
        )
        await session.commit()
        return DHCPManagerState.NOT_CONFIGURED

    return DHCPManagerState(state.value)
