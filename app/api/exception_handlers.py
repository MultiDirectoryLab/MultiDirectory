"""Exception handlers."""

from typing import NoReturn

from fastapi import HTTPException, Request, status
from loguru import logger


# NOTE: the function signature matches starlette.types.ExceptionHandler
def handle_db_connect_error(
    request: Request,  # noqa: ARG001
    exc: Exception,
) -> NoReturn:
    """Handle duplicate."""
    if "QueuePool limit of size" in str(exc):
        logger.critical("POOL EXCEEDED {}", exc)

        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Connection Pool Exceeded",
        )

    logger.critical("DB BACKEND ERR {}", exc)

    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)


# NOTE: the function signature matches starlette.types.ExceptionHandler
async def handle_dns_error(
    request: Request,  # noqa: ARG001
    exc: Exception,
) -> NoReturn:
    """Handle EmptyLabel exception."""
    logger.critical("DNS manager error: {}", exc)
    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)
