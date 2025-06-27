"""Exception handlers."""

from typing import NoReturn

from fastapi import HTTPException, Request, status
from loguru import logger


def handle_db_connect_error(
    request: Request,  # noqa: ARG001
    exc: Exception,
) -> NoReturn:
    """Handle database connection errors.

    Args:
        request (Request): FastAPI request object.
        exc (Exception): Exception instance.

    Raises:
        HTTPException: If connection pool is exceeded or backend error occurs.
    """
    if "QueuePool limit of size" in str(exc):
        logger.critical("POOL EXCEEDED {}", exc)

        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Connection Pool Exceeded",
        )

    logger.critical("DB BACKEND ERR {}", exc)

    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)


async def handle_dns_error(
    request: Request,  # noqa: ARG001
    exc: Exception,
) -> NoReturn:
    """Handle DNS-related errors.

    Args:
        request (Request): FastAPI request object.
        exc (Exception): Exception instance.

    Raises:
        HTTPException: Always raised for DNS errors.
    """
    logger.critical("DNS manager error: {}", exc)
    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)


async def handle_instance_not_found_error(
    request: Request,  # noqa: ARG001
    exc: Exception,  # noqa: ARG001
) -> NoReturn:
    """Handle Instance Not Found error.

    Args:
        request (Request): request
        exc (Exception): exc.

    Raises:
        HTTPException: Instance not found.
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Instance not found.",
    )


async def handle_instance_cant_modify_error(
    request: Request,  # noqa: ARG001
    exc: Exception,  # noqa: ARG001
) -> NoReturn:
    """Handle Instance Cant Modify error.

    Args:
        request (Request): request
        exc (Exception): exc.

    Raises:
        HTTPException: System Instance cannot be modified.
    """
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="System Instance cannot be modified.",
    )


async def handle_not_implemented_error(
    request: Request,  # noqa: ARG001
    exc: Exception,  # noqa: ARG001
) -> NoReturn:
    """Handle Not Implemented error."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="This feature is supported with selfhosted DNS server.",
    )
