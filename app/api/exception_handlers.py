"""Exception handlers."""

from typing import NoReturn

from fastapi import HTTPException, Request, status
from loguru import logger


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


async def handle_dns_error(
    request: Request,  # noqa: ARG001
    exc: Exception,
) -> NoReturn:
    """Handle EmptyLabel exception."""
    logger.critical("DNS manager error: {}", exc)
    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE)


async def handle_instance_not_found_error(
    request: Request,  # noqa: ARG001
    exc: Exception,
) -> NoReturn:
    """Handle Instance Not Found error."""
    logger.error("Instance not found.", exc)
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Instance not found.",
    )


async def handle_object_class_kind_not_valid(
    request: Request,  # noqa: ARG001
    exc: Exception,
) -> NoReturn:
    """Handle Object Class Kind Not Valid error."""
    logger.error("Object Class kind is not valid.", exc)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Object Class kind is not valid.",
    )


async def handle_instance_cant_modify_error(
    request: Request,  # noqa: ARG001
    exc: Exception,
) -> NoReturn:
    """Handle Instance Cant Modify error."""
    logger.error("System Instance cannot be modified.", exc)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="System Instance cannot be modified.",
    )
