"""Utils for DNS server API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import functools
from typing import Any, Callable

from .base import DNSConnectionError, log


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
