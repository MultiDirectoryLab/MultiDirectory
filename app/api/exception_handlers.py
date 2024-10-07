"""Exception handlers."""

from typing import NoReturn

import dns.name
from fastapi import HTTPException, Request, status
from loguru import logger
from sqlalchemy import exc


def handle_db_connect_error(
    request: Request,
    exc: exc.TimeoutError | exc.InterfaceError,
) -> NoReturn:
    """Handle duplicate."""
    if "QueuePool limit of size" in str(exc):
        logger.critical('POOL EXCEEDED {}', exc)

        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail='Connection Pool Exceeded')

    logger.critical('DB BACKEND ERR {}', exc)

    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)


async def handle_dns_error(
    request: Request,
    exc: dns.exception.DNSException,
) -> NoReturn:
    """Handle EmptyLabel exception."""

    logger.critical("DNS manager error: {}", exc)

    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)